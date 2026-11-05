/* OSINT Dashboard UI. Depends on window.OSINT_DATA (data/tools.js) and window.OsintCore (assets/core.js).
 * No network access, no third-party code. All state lives in this browser's localStorage. */
(function () {
  'use strict';

  var APP_VERSION = '3.0.0';
  var PREFS_KEY = 'osint.prefs.v3';
  var LEGACY_KEYS = ['osintToolOrder', 'toolConfigVersion'];
  var DATA = window.OSINT_DATA;
  var Core = window.OsintCore;

  if (!DATA || !Core) {
    document.getElementById('sections').textContent = 'Failed to load the tool catalogue. Reload the page; if it persists, report it on GitHub.';
    return;
  }

  /* ------------------------------------------------------------------ helpers */
  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  function h(tag, attrs, children) {
    var el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === false || v == null) return;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else el.setAttribute(k, v === true ? '' : v);
    });
    (children || []).forEach(function (c) { if (c) el.append(c); });
    return el;
  }
  function svg(markup) {
    var t = document.createElement('template');
    t.innerHTML = markup; // static, developer-authored markup only
    return t.content.firstElementChild;
  }
  var ICON_STAR = '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M12 3.5l2.6 5.5 6 .8-4.4 4.2 1.1 6-5.3-2.9-5.3 2.9 1.1-6L3.4 9.8l6-.8z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>';
  var ICON_COPY = '<svg viewBox="0 0 24 24" width="17" height="17" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M5 15V6a2 2 0 012-2h9" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
  var ICON_CHEV = '<svg class="chev" viewBox="0 0 20 20" aria-hidden="true"><path d="M5 8l5 5 5-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function debounce(fn, ms) { var t; return function () { var a = arguments, c = this; clearTimeout(t); t = setTimeout(function () { fn.apply(c, a); }, ms); }; }

  /* ------------------------------------------------------------------ storage */
  var storageOk = true;
  function readPrefs() {
    try { return JSON.parse(localStorage.getItem(PREFS_KEY)) || null; }
    catch (e) { storageOk = false; return null; }
  }
  function writePrefs() {
    try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); }
    catch (e) { if (storageOk) { storageOk = false; toast('Browser storage is unavailable; settings will not persist.', 'warn'); } }
  }

  /* ------------------------------------------------------------------ catalogue indexes */
  var TOOLS = DATA.tools;
  var BY_ID = {};
  TOOLS.forEach(function (t) { BY_ID[t.id] = t; });
  var CAT_TITLE = {};
  DATA.categories.forEach(function (c) { CAT_TITLE[c.id] = c.title; });

  var NAME_INDEX = {}; // legacy name -> id (first wins), used to migrate pre-v3 favorites
  TOOLS.forEach(function (t) {
    [t.name].concat(t.aliases || []).forEach(function (n) {
      var k = n.trim().toLowerCase();
      if (!NAME_INDEX[k]) NAME_INDEX[k] = t.id;
    });
  });

  var TYPE_LABEL = { ip: 'IP', domain: 'Domain', url: 'URL', email: 'Email', hash: 'Hash', cve: 'CVE', asn: 'ASN', cidr: 'CIDR', text: 'Text', all: 'Any input', any: 'Reference' };
  var KIND_LABEL = {
    empty: 'No indicator', ipv4: 'IPv4 address', ipv6: 'IPv6 address', cidr: 'CIDR range', domain: 'Domain', url: 'URL',
    email: 'Email address', md5: 'MD5 hash', sha1: 'SHA-1 hash', sha256: 'SHA-256 hash', sha512: 'SHA-512 hash',
    cve: 'CVE ID', asn: 'AS number', text: 'Free text / username'
  };

  /* ------------------------------------------------------------------ state */
  var DEFAULTS = {
    theme: 'system', favorites: null, collapsed: [], view: 'all', opsec: 'any', nologin: false,
    historyOn: false, history: [], noticeDismissed: false
  };
  var prefs = loadPrefs();
  var ioc = Core.parse('');
  var filterText = '';

  function loadPrefs() {
    var stored = readPrefs();
    var p = Object.assign({}, DEFAULTS, stored || {});
    if (!stored) migrateLegacy(p);
    // sanitize anything that came from storage
    p.theme = ['system', 'light', 'dark'].indexOf(p.theme) >= 0 ? p.theme : 'system';
    p.view = ['all', 'applies', 'fav'].indexOf(p.view) >= 0 ? p.view : 'all';
    p.opsec = p.opsec === 'passive' ? 'passive' : 'any';
    p.collapsed = Array.isArray(p.collapsed) ? p.collapsed.filter(function (x) { return typeof x === 'string'; }) : [];
    p.history = Array.isArray(p.history) ? p.history.filter(function (x) { return typeof x === 'string'; }).slice(0, 15) : [];
    if (p.favorites !== null) p.favorites = uniq((Array.isArray(p.favorites) ? p.favorites : []).filter(function (id) { return BY_ID[id]; }));
    return p;
  }
  function uniq(a) { return a.filter(function (x, i) { return a.indexOf(x) === i; }); }

  /** Pre-v3 builds stored { "YOUR FAVORITES": ["Virus Total", ...] } by display name. Carry favorites over. */
  function migrateLegacy(p) {
    try {
      var old = JSON.parse(localStorage.getItem('osintToolOrder') || 'null');
      var names = old && old['YOUR FAVORITES'];
      if (Array.isArray(names)) {
        var ids = uniq(names.map(function (n) { return NAME_INDEX[String(n).trim().toLowerCase()]; }).filter(Boolean));
        if (ids.length) p.favorites = ids;
      }
      LEGACY_KEYS.forEach(function (k) { localStorage.removeItem(k); });
    } catch (e) { /* ignore corrupt legacy data */ }
  }

  function favorites() { return prefs.favorites === null ? DATA.defaultFavorites.slice() : prefs.favorites; }
  function isFav(id) { return favorites().indexOf(id) >= 0; }
  function setFavorites(list) { prefs.favorites = uniq(list); writePrefs(); }

  /* ------------------------------------------------------------------ theme */
  var mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;
  function effectiveTheme() { return prefs.theme === 'system' ? (mq && mq.matches ? 'light' : 'dark') : prefs.theme; }
  function applyTheme() {
    var root = document.documentElement;
    if (prefs.theme === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', prefs.theme);
    var next = effectiveTheme() === 'dark' ? 'light' : 'dark';
    $('#theme-toggle').setAttribute('aria-label', 'Switch to ' + next + ' theme');
  }
  function toggleTheme() { prefs.theme = effectiveTheme() === 'dark' ? 'light' : 'dark'; writePrefs(); applyTheme(); }

  /* ------------------------------------------------------------------ toasts / clipboard */
  function toast(msg, tone) {
    var box = $('#toasts');
    var el = h('div', { class: 'toast', 'data-tone': tone || 'info', text: msg });
    box.append(el);
    while (box.children.length > 4) box.firstChild.remove();
    setTimeout(function () { el.remove(); }, tone === 'warn' || tone === 'error' ? 6000 : 3000);
  }
  function copyText(text, okMsg) {
    var done = function () { toast(okMsg || 'Copied to clipboard', 'ok'); };
    var fallback = function () {
      var ta = h('textarea', { 'aria-hidden': 'true', tabindex: '-1' });
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.append(ta); ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      ta.remove();
      if (ok) done(); else toast('Copy failed. Select the link and copy it manually.', 'error');
    };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fallback);
    else fallback();
  }

  /* ------------------------------------------------------------------ filtering */
  function toolHref(tool) {
    var u = Core.buildUrl(tool, ioc);
    return /^https:\/\//i.test(u) ? u : tool.url;
  }
  function textHaystack(t) {
    if (!t._hay) t._hay = [t.name, t.desc, t.id, (t.aliases || []).join(' '), (t.types || []).join(' '), CAT_TITLE[t.cat], t.opsec || '', t.auth ? 'login account' : ''].join(' ').toLowerCase();
    return t._hay;
  }
  function visible(t, opts) {
    opts = opts || {};
    if (filterText) {
      var words = filterText.split(/\s+/);
      var hay = textHaystack(t);
      for (var i = 0; i < words.length; i++) if (hay.indexOf(words[i]) < 0) return false;
    }
    if (prefs.opsec === 'passive' && t.opsec) return false;
    if (prefs.nologin && t.auth) return false;
    if (prefs.view === 'applies' && !Core.accepts(t, ioc)) return false;
    if (prefs.view === 'fav' && !opts.inFavSection && !isFav(t.id)) return false;
    return true;
  }

  /* ------------------------------------------------------------------ rendering */
  var ioHandle = null;

  function render() {
    var active = document.activeElement;
    var focusKey = active && active.closest && active.closest('#sections') ? active.getAttribute('data-key') : null;

    var host = $('#sections');
    host.textContent = '';
    var favs = favorites().map(function (id) { return BY_ID[id]; }).filter(Boolean);
    var counts = {};
    var shown = 0, applicable = 0;

    // Favorites (virtual section, always first)
    var favVisible = favs.filter(function (t) { return visible(t, { inFavSection: true }); });
    host.append(buildSection({ id: 'fav', title: 'Favorites', note: favs.length ? 'Opened together with “Open favorites”' : '' }, favVisible, favs.length === 0));
    counts.fav = favVisible.length;

    DATA.categories.forEach(function (c) {
      var list = TOOLS.filter(function (t) { return t.cat === c.id && visible(t); });
      counts[c.id] = list.length;
      shown += list.length;
      if (list.length) host.append(buildSection(c, list));
    });
    TOOLS.forEach(function (t) { if (Core.accepts(t, ioc) && !t.ref) applicable++; });

    $('#empty').hidden = shown > 0 || favVisible.length > 0;
    renderNav(counts);
    renderJump(counts);
    renderSummary(shown, applicable);
    observeSections();

    if (focusKey) {
      var again = $('[data-key="' + focusKey.replace(/"/g, '\\"') + '"]', host);
      if (again) again.focus({ preventScroll: true });
    }
  }

  function buildSection(cat, list, emptyFavs) {
    var forceOpen = !!filterText;
    var collapsed = !forceOpen && prefs.collapsed.indexOf(cat.id) >= 0;
    var gridId = 'grid-' + cat.id;
    var toggle = h('button', { type: 'button', class: 'section-toggle', 'aria-expanded': String(!collapsed), 'aria-controls': gridId, 'data-key': 'toggle:' + cat.id });
    toggle.append(svg(ICON_CHEV), h('h2', { text: cat.title }), h('span', { class: 'section-count', text: String(list.length) }));
    toggle.addEventListener('click', function () { toggleSection(cat.id); });

    var head = h('div', { class: 'section-head' }, [toggle, cat.note ? h('span', { class: 'section-note', text: cat.note }) : null, h('span', { class: 'section-rule' })]);
    var grid = h('div', { class: 'grid', id: gridId });
    if (collapsed) grid.hidden = true;
    if (emptyFavs) grid.append(h('p', { class: 'empty-fav', text: 'No favorites yet. Use the star on any tool to pin it here.' }));
    list.forEach(function (t, i) { grid.append(buildCard(t, cat.id === 'fav' ? { index: i, total: list.length } : null)); });
    return h('section', { class: 'section', id: 'cat-' + cat.id, 'data-cat': cat.id, 'aria-label': cat.title }, [head, grid]);
  }

  function badge(text, cls, title) { return h('span', { class: 'badge ' + cls, text: text, title: title }); }

  function buildCard(t, favPos) {
    var href = toolHref(t);
    var applies = Core.accepts(t, ioc);
    var muted = ioc.kind !== 'empty' && !applies;

    var link = h('a', { class: 'card-link', href: href, target: '_blank', rel: 'noopener noreferrer', text: t.name, 'data-key': (favPos ? 'open-fav:' : 'open:') + t.id });
    if (muted) link.setAttribute('aria-description', 'Does not accept the current indicator type');

    var fav = isFav(t.id);
    var star = h('button', { type: 'button', class: 'icon-btn', 'aria-pressed': String(fav), 'aria-label': (fav ? 'Remove ' : 'Add ') + t.name + (fav ? ' from favorites' : ' to favorites'), title: fav ? 'Remove from favorites' : 'Add to favorites', 'data-key': (favPos ? 'star-fav:' : 'star:') + t.id });
    star.append(svg(ICON_STAR));
    star.addEventListener('click', function () { toggleFav(t.id); });

    var copy = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Copy link for ' + t.name, title: 'Copy link', 'data-key': (favPos ? 'copy-fav:' : 'copy:') + t.id });
    copy.append(svg(ICON_COPY));
    copy.addEventListener('click', function () { copyText(toolHref(t), 'Link copied'); });

    var actions = h('div', { class: 'card-actions' });
    if (favPos) {
      var left = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Move ' + t.name + ' earlier', title: 'Move earlier', text: '‹', disabled: favPos.index === 0, 'data-key': 'mv-l:' + t.id });
      var right = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Move ' + t.name + ' later', title: 'Move later', text: '›', disabled: favPos.index === favPos.total - 1, 'data-key': 'mv-r:' + t.id });
      left.addEventListener('click', function () { moveFav(t.id, -1); });
      right.addEventListener('click', function () { moveFav(t.id, 1); });
      actions.append(left, right);
    }
    actions.append(copy, star);

    var meta = h('div', { class: 'card-meta' });
    if (t.ref) meta.append(badge('Reference', 'badge-ref', 'Opens the tool; does not take an indicator'));
    else (t.types || []).slice(0, 4).forEach(function (ty) { meta.append(badge(TYPE_LABEL[ty] || ty, 'badge-type', 'Accepts ' + (TYPE_LABEL[ty] || ty))); });
    if (t.opsec === 'active') meta.append(badge('Active', 'badge-active', 'Makes the vendor contact the target. Your interest may be visible to it.'));
    if (t.opsec === 'submit') meta.append(badge('Submits', 'badge-submit', 'Uploaded or submitted data may be shared publicly.'));
    if (t.auth) meta.append(badge('Login', 'badge-auth', 'Free or paid account usually required.'));

    var hostMatch = /^https?:\/\/([^/?#]+)/i.exec(t.url);
    var kids = [h('div', { class: 'card-top' }, [link, actions]), h('p', { class: 'card-desc', text: t.desc || '' })];
    if (t.note && muted === false && ioc.kind !== 'empty' && t.routes && t.routes[ioc.cls]) kids.push(h('p', { class: 'card-desc', text: t.note }));
    kids.push(meta);
    if (hostMatch) kids.push(h('span', { class: 'card-host', text: hostMatch[1].replace(/^www\./, '') }));

    return h('article', { class: 'card' + (muted ? ' is-muted' : ''), 'data-id': t.id }, kids);
  }

  function renderNav(counts) {
    var nav = $('#sidebar');
    nav.textContent = '';
    var top = h('div', { class: 'nav-group' });
    top.append(navLink('fav', 'Favorites', counts.fav));
    nav.append(top);
    var groups = [];
    DATA.categories.forEach(function (c) { if (groups.indexOf(c.group) < 0) groups.push(c.group); });
    groups.forEach(function (g) {
      var box = h('div', { class: 'nav-group' }, [h('h2', { text: g })]);
      DATA.categories.filter(function (c) { return c.group === g; }).forEach(function (c) { box.append(navLink(c.id, c.title, counts[c.id])); });
      nav.append(box);
    });
  }
  function navLink(id, title, n) {
    var a = h('a', { class: 'nav-link' + (n ? '' : ' is-empty'), href: '#cat-' + id, 'data-nav': id }, [h('span', { text: title }), h('span', { class: 'count', text: String(n || 0) })]);
    a.addEventListener('click', function (e) {
      e.preventDefault();
      var sec = document.getElementById('cat-' + id);
      if (!sec) return;
      if (prefs.collapsed.indexOf(id) >= 0) toggleSection(id);
      document.getElementById('cat-' + id).scrollIntoView({ block: 'start' });
    });
    return a;
  }
  function renderJump(counts) {
    var sel = $('#jump');
    var cur = sel.value;
    sel.textContent = '';
    sel.append(h('option', { value: '', text: 'Jump to category…' }));
    sel.append(h('option', { value: 'fav', text: 'Favorites (' + (counts.fav || 0) + ')' }));
    DATA.categories.forEach(function (c) { if (counts[c.id]) sel.append(h('option', { value: c.id, text: c.title + ' (' + counts[c.id] + ')' })); });
    sel.value = cur && $('option[value="' + cur + '"]', sel) ? cur : '';
  }

  var activeNav = null;
  function observeSections() {
    if (ioHandle) ioHandle.disconnect();
    if (!('IntersectionObserver' in window)) return;
    ioHandle = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) setActiveNav(en.target.getAttribute('data-cat')); });
    }, { rootMargin: '-15% 0px -75% 0px' });
    $$('.section').forEach(function (s) { ioHandle.observe(s); });
    if (activeNav) setActiveNav(activeNav);
  }
  function setActiveNav(id) {
    activeNav = id;
    $$('.nav-link').forEach(function (a) { if (a.getAttribute('data-nav') === id) a.setAttribute('aria-current', 'true'); else a.removeAttribute('aria-current'); });
  }

  function renderSummary(shown, applicable) {
    var el = $('#summary');
    var searchable = TOOLS.filter(function (t) { return !t.ref; }).length;
    var msg;
    if (ioc.kind === 'empty') {
      msg = TOOLS.length + ' tools in ' + DATA.categories.length + ' categories. Enter an indicator above to build lookup links for ' + searchable + ' searchable tools.';
    } else {
      msg = 'Detected ' + KIND_LABEL[ioc.kind] + ': ' + applicable + ' of ' + searchable + ' searchable tools accept it. Showing ' + shown + '.';
      if (ioc.value !== ioc.raw.trim()) msg += ' Refanged to ' + ioc.value + '.';
      if (ioc.kind === 'text') msg += ' Not recognized as an IP, domain, URL, email, hash, CVE or ASN; tools that accept free text are highlighted.';
    }
    el.textContent = msg;
  }

  function renderIocChip() {
    var chip = $('#ioc-type');
    chip.textContent = KIND_LABEL[ioc.kind];
    chip.setAttribute('data-kind', ioc.kind);
    $('#ioc-clear').hidden = ioc.kind === 'empty';
  }

  /* ------------------------------------------------------------------ actions */
  function toggleSection(id) {
    var i = prefs.collapsed.indexOf(id);
    if (i >= 0) prefs.collapsed.splice(i, 1); else prefs.collapsed.push(id);
    writePrefs();
    var sec = document.getElementById('cat-' + id);
    if (!sec) return;
    var collapsed = prefs.collapsed.indexOf(id) >= 0;
    $('.section-toggle', sec).setAttribute('aria-expanded', String(!collapsed));
    $('.grid', sec).hidden = collapsed;
  }

  function toggleFav(id) {
    var list = favorites().slice();
    var i = list.indexOf(id);
    if (i >= 0) list.splice(i, 1); else list.push(id);
    setFavorites(list);
    render();
    toast((i >= 0 ? 'Removed ' : 'Added ') + BY_ID[id].name + (i >= 0 ? ' from' : ' to') + ' favorites', 'ok');
  }
  function moveFav(id, dir) {
    var list = favorites().slice();
    var i = list.indexOf(id), j = i + dir;
    if (i < 0 || j < 0 || j >= list.length) return;
    list.splice(j, 0, list.splice(i, 1)[0]);
    setFavorites(list);
    render();
  }

  function openFavorites() {
    if (ioc.kind === 'empty') { toast('Enter an indicator first, then open your favorites.', 'warn'); $('#ioc').focus(); return; }
    var targets = favorites().map(function (id) { return BY_ID[id]; }).filter(function (t) { return t && !t.ref && Core.accepts(t, ioc); });
    if (!targets.length) { toast('None of your favorites accept a ' + KIND_LABEL[ioc.kind].toLowerCase() + '.', 'warn'); return; }
    var risky = targets.filter(function (t) { return t.opsec === 'active'; }).map(function (t) { return t.name; });
    var msg = 'Open ' + targets.length + ' tab' + (targets.length === 1 ? '' : 's') + ' and send this indicator to ' + targets.length + ' third-party site' + (targets.length === 1 ? '' : 's') + '?';
    if (risky.length) msg += '\n\nActive tools (they contact the target): ' + risky.join(', ') + '.';
    if (targets.length > 1 || risky.length) { if (!window.confirm(msg)) return; }
    var blocked = 0;
    targets.forEach(function (t) {
      var w = window.open(toolHref(t), '_blank');
      if (w) { try { w.opener = null; } catch (e) { /* cross-origin */ } } else blocked++;
    });
    if (blocked) toast(blocked + ' tab(s) were blocked by the browser. Allow pop-ups for this site and try again.', 'warn');
    else toast('Opened ' + targets.length + ' favorite' + (targets.length === 1 ? '' : 's'), 'ok');
  }

  function shareLink() {
    if (ioc.kind === 'empty') { toast('Nothing to share yet. Enter an indicator first.', 'warn'); return; }
    var url = location.origin === 'null' || location.protocol === 'file:' ? location.href.split(/[?#]/)[0] : location.origin + location.pathname;
    copyText(url + '?q=' + encodeURIComponent(ioc.value), 'Share link copied');
  }

  /* ------------------------------------------------------------------ history */
  function renderHistory() {
    var dl = $('#ioc-history');
    dl.textContent = '';
    if (prefs.historyOn) prefs.history.forEach(function (v) { dl.append(h('option', { value: v })); });
  }
  function remember(value) {
    if (!prefs.historyOn || !value) return;
    prefs.history = [value].concat(prefs.history.filter(function (x) { return x !== value; })).slice(0, 15);
    writePrefs(); renderHistory();
  }

  /* ------------------------------------------------------------------ indicator input */
  var input = $('#ioc');
  function onIocInput() {
    ioc = Core.parse(input.value);
    renderIocChip();
    render();
  }
  var onIocInputSoon = debounce(onIocInput, 60);

  function setIoc(value) { input.value = value; onIocInput(); }

  /* ------------------------------------------------------------------ settings dialogs / import / export */
  function syncSettingsForm() {
    $$('input[name="theme"]').forEach(function (r) { r.checked = r.value === prefs.theme; });
    $('#set-history').checked = prefs.historyOn;
  }
  function exportPrefs() {
    var out = { app: 'osint-dashboard', schema: 3, exported: new Date().toISOString(), theme: prefs.theme, favorites: favorites(), collapsed: prefs.collapsed, view: prefs.view, opsec: prefs.opsec, nologin: prefs.nologin };
    var blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' });
    var a = h('a', { href: URL.createObjectURL(blob), download: 'osint-dashboard-settings.json' });
    document.body.append(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    toast('Settings exported', 'ok');
  }
  function importPrefs(file) {
    if (!file) return;
    if (file.size > 200 * 1024) { toast('That file is too large to be a settings export.', 'error'); return; }
    var fr = new FileReader();
    fr.onload = function () {
      try {
        var d = JSON.parse(String(fr.result));
        if (!d || typeof d !== 'object' || d.app !== 'osint-dashboard') throw new Error('not an OSINT Dashboard export');
        var favs = Array.isArray(d.favorites) ? d.favorites.filter(function (id) { return BY_ID[id]; }) : null;
        if (favs) prefs.favorites = uniq(favs);
        if (['system', 'light', 'dark'].indexOf(d.theme) >= 0) prefs.theme = d.theme;
        if (Array.isArray(d.collapsed)) prefs.collapsed = d.collapsed.filter(function (x) { return typeof x === 'string'; });
        if (['all', 'applies', 'fav'].indexOf(d.view) >= 0) prefs.view = d.view;
        if (d.opsec === 'passive' || d.opsec === 'any') prefs.opsec = d.opsec;
        prefs.nologin = !!d.nologin;
        writePrefs(); applyTheme(); syncControls(); syncSettingsForm(); render();
        toast('Settings imported', 'ok');
      } catch (e) { toast('Import failed: ' + e.message, 'error'); }
    };
    fr.onerror = function () { toast('Could not read that file.', 'error'); };
    fr.readAsText(file);
  }
  function resetAll() {
    if (!window.confirm('Reset favorites, theme, layout and recent indicators to defaults?')) return;
    prefs = Object.assign({}, DEFAULTS);
    try { localStorage.removeItem(PREFS_KEY); LEGACY_KEYS.forEach(function (k) { localStorage.removeItem(k); }); } catch (e) { /* ignore */ }
    applyTheme(); syncControls(); syncSettingsForm(); renderHistory(); render();
    toast('Reset to defaults', 'ok');
  }

  /* ------------------------------------------------------------------ control wiring */
  function syncControls() {
    $$('#seg-view button').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-view') === prefs.view)); });
    $$('#seg-opsec button').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-opsec') === prefs.opsec)); });
    $('#chk-nologin').checked = prefs.nologin;
    $('#opsec-notice').hidden = prefs.noticeDismissed;
  }

  function wire() {
    input.addEventListener('input', onIocInputSoon);
    $('#ioc-form').addEventListener('submit', function (e) { e.preventDefault(); onIocInput(); if (ioc.kind !== 'empty') { remember(ioc.value); toast('Links updated for ' + KIND_LABEL[ioc.kind].toLowerCase(), 'ok'); } });
    $('#ioc-clear').addEventListener('click', function () { setIoc(''); input.focus(); });

    var filter = $('#filter');
    filter.addEventListener('input', debounce(function () { filterText = filter.value.trim().toLowerCase(); render(); }, 80));

    $('#jump').addEventListener('change', function (e) {
      var id = e.target.value; if (!id) return;
      if (prefs.collapsed.indexOf(id) >= 0) toggleSection(id);
      var sec = document.getElementById('cat-' + id); if (sec) sec.scrollIntoView({ block: 'start' });
      e.target.value = '';
    });

    $('#seg-view').addEventListener('click', function (e) { var b = e.target.closest('button'); if (!b) return; prefs.view = b.getAttribute('data-view'); writePrefs(); syncControls(); render(); });
    $('#seg-opsec').addEventListener('click', function (e) { var b = e.target.closest('button'); if (!b) return; prefs.opsec = b.getAttribute('data-opsec'); writePrefs(); syncControls(); render(); });
    $('#chk-nologin').addEventListener('change', function (e) { prefs.nologin = e.target.checked; writePrefs(); render(); });
    $('#btn-open-fav').addEventListener('click', openFavorites);
    $('#btn-share').addEventListener('click', shareLink);
    $('#btn-hide-notice').addEventListener('click', function () { prefs.noticeDismissed = true; writePrefs(); syncControls(); });

    $('#theme-toggle').addEventListener('click', toggleTheme);
    if (mq && mq.addEventListener) mq.addEventListener('change', function () { if (prefs.theme === 'system') applyTheme(); });

    var dlgS = $('#dlg-settings'), dlgK = $('#dlg-shortcuts');
    $('#btn-settings').addEventListener('click', function () { syncSettingsForm(); dlgS.showModal(); });
    $('#btn-shortcuts').addEventListener('click', function () { dlgK.showModal(); });
    [dlgS, dlgK].forEach(function (d) { d.addEventListener('click', function (e) { if (e.target === d) d.close(); }); });
    $$('input[name="theme"]').forEach(function (r) { r.addEventListener('change', function () { prefs.theme = r.value; writePrefs(); applyTheme(); }); });
    $('#set-history').addEventListener('change', function (e) {
      prefs.historyOn = e.target.checked; if (!prefs.historyOn) prefs.history = [];
      writePrefs(); renderHistory();
    });
    $('#btn-clear-history').addEventListener('click', function () { prefs.history = []; writePrefs(); renderHistory(); toast('Recent indicators cleared', 'ok'); });
    $('#btn-export').addEventListener('click', exportPrefs);
    $('#btn-import').addEventListener('click', function () { $('#file-import').click(); });
    $('#file-import').addEventListener('change', function (e) { importPrefs(e.target.files[0]); e.target.value = ''; });
    $('#btn-reset').addEventListener('click', resetAll);

    document.addEventListener('keydown', function (e) {
      var tgt = e.target;
      var typing = tgt && (/^(INPUT|TEXTAREA|SELECT)$/.test(tgt.tagName) || tgt.isContentEditable);
      if (e.key === 'Escape' && typing && (tgt === input || tgt === filter)) {
        if (tgt.value) { tgt.value = ''; tgt.dispatchEvent(new Event('input')); } else tgt.blur();
        return;
      }
      if (typing || e.ctrlKey || e.metaKey || e.altKey || document.querySelector('dialog[open]')) return;
      switch (e.key) {
        case '/': e.preventDefault(); input.focus(); input.select(); break;
        case 'f': e.preventDefault(); filter.focus(); filter.select(); break;
        case 't': toggleTheme(); break;
        case 'o': openFavorites(); break;
        case '?': dlgK.showModal(); break;
      }
    });
  }

  /* ------------------------------------------------------------------ boot */
  applyTheme();
  syncControls();
  renderHistory();
  $('#app-version').textContent = 'OSINT Dashboard v' + APP_VERSION + ' · ' + TOOLS.length + ' tools';
  wire();

  var params = new URLSearchParams(location.search);
  var initial = params.get('q') || params.get('ip') || params.get('ioc') || '';
  if (initial) { input.value = initial.slice(0, 2048); ioc = Core.parse(input.value); renderIocChip(); }
  render();
})();
