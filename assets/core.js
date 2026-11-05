/* OSINT Dashboard core: pure functions, no DOM access.
 * Loaded in the browser as window.OsintCore and in Node (tests) via require().
 */
(function (root) {
  'use strict';

  var HASH_LEN = { 32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512' };

  /** Undo common "defanging" so pasted threat-report IOCs work: hxxp, [.], (.), [dot], [@], [:] */
  function refang(input) {
    var s = String(input == null ? '' : input).trim();
    s = s.replace(/^[<"'`(\[]+|[>"'`)\]]+$/g, '');           // wrapping quotes / brackets
    s = s.replace(/^hxxp(s?)(:|\[:\]|\[:)/i, 'http$1:');
    s = s.replace(/^fxp(s?):/i, 'ftp$1:');
    s = s.replace(/\[\s*:\s*\]/g, ':')
         .replace(/\[\s*\/\/\s*\]/g, '//')
         .replace(/\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}/gi, '.')
         .replace(/\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)/gi, '@');
    return s.trim();
  }

  function isIPv4(s) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (!m) return false;
    for (var i = 1; i <= 4; i++) {
      if (+m[i] > 255 || (m[i].length > 1 && m[i][0] === '0')) return false;
    }
    return true;
  }

  function isIPv6(s) {
    if (!/^[0-9a-f:.]+$/i.test(s) || s.indexOf(':') === -1) return false;
    var tail = s.split(':').pop();
    var groups = s;
    var extra = 0;
    if (tail.indexOf('.') !== -1) {                          // IPv4-mapped tail (::ffff:1.2.3.4)
      if (!isIPv4(tail)) return false;
      groups = s.slice(0, s.length - tail.length) + '0:0';
      extra = 0;
    }
    var dbl = groups.split('::');
    if (dbl.length > 2) return false;
    var parts = function (x) { return x === '' ? [] : x.split(':'); };
    var head = parts(dbl[0]);
    var rest = dbl.length === 2 ? parts(dbl[1]) : [];
    var all = head.concat(rest);
    for (var i = 0; i < all.length; i++) {
      if (!/^[0-9a-f]{1,4}$/i.test(all[i])) return false;
    }
    var n = all.length + extra;
    return dbl.length === 2 ? n < 8 : n === 8;
  }

  var DOMAIN_RE = /^(?:[\p{L}\p{N}_](?:[\p{L}\p{N}_-]{0,61}[\p{L}\p{N}_])?\.)+(?:xn--[a-z0-9-]{1,59}|[\p{L}]{2,63})$/iu;

  function stripScheme(v) {
    return v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/\/+$/, '');
  }

  function hostOf(v, kind) {
    var s = stripScheme(v);
    if (kind === 'ipv6' || kind === 'cidr') return s;
    s = s.split(/[/?#]/)[0];
    s = s.replace(/^[^@]*@/, '');                            // userinfo
    if (s[0] === '[') return s.slice(1, s.indexOf(']'));     // [::1]:8080
    return s.replace(/:\d+$/, '');
  }

  /**
   * Classify an indicator.
   * kind: ipv4 | ipv6 | cidr | domain | url | email | md5 | sha1 | sha256 | sha512 | cve | asn | text | empty
   * cls : ip | cidr | domain | url | email | hash | cve | asn | text | empty   (coarser, used by tool routes)
   */
  function parse(input) {
    var raw = String(input == null ? '' : input);
    var value = refang(raw);
    var out = { raw: raw, value: value, kind: 'empty', cls: 'empty', clean: '', host: '', hostname: '' };
    if (!value) return out;

    var kind = 'text';
    var m;
    if (/^CVE-\d{4}-\d{4,}$/i.test(value)) { kind = 'cve'; value = value.toUpperCase(); }
    else if (/^AS\d{1,10}$/i.test(value)) { kind = 'asn'; value = value.toUpperCase(); }
    else if (/^[0-9a-f]+$/i.test(value) && HASH_LEN[value.length]) { kind = HASH_LEN[value.length]; value = value.toLowerCase(); }
    else if (isIPv4(value)) kind = 'ipv4';
    else if (isIPv6(value)) kind = 'ipv6';
    else if ((m = /^(.+)\/(\d{1,3})$/.exec(value)) && ((isIPv4(m[1]) && +m[2] <= 32) || (isIPv6(m[1]) && +m[2] <= 128))) kind = 'cidr';
    else if (/^[^\s@/]+@[^\s@/]+\.[^\s@/]{2,}$/.test(value)) kind = 'email';
    else if (/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(value)) kind = 'url';
    else if (DOMAIN_RE.test(value)) kind = 'domain';
    else if (/^[^\s/]+\.[a-z]{2,}(?::\d+)?[/?#]\S*$/i.test(value) || /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\/(?!\d+$)\S+$/.test(value)) kind = 'url';

    var cls = kind;
    if (kind === 'ipv4' || kind === 'ipv6') cls = 'ip';
    else if (kind === 'md5' || kind === 'sha1' || kind === 'sha256' || kind === 'sha512') cls = 'hash';

    out.value = value;
    out.kind = kind;
    out.cls = cls;
    out.clean = stripScheme(value);
    if (kind === 'url' || kind === 'domain' || kind === 'ipv4' || kind === 'ipv6') out.host = hostOf(value, kind);
    else if (kind === 'email') out.host = value.split('@').pop();
    out.hostname = out.host;
    return out;
  }

  function utf8Bytes(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    return Array.prototype.slice.call(Buffer.from(str, 'utf8'));
  }

  /** UTF-8 safe base64 (btoa throws on non-Latin-1 input). */
  function b64(str) {
    var bytes = utf8Bytes(str);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return typeof btoa === 'function' ? btoa(bin) : Buffer.from(bin, 'binary').toString('base64');
  }

  function hex(str) {
    var bytes = utf8Bytes(str), out = '';
    for (var i = 0; i < bytes.length; i++) out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return out;
  }

  var TOKEN_RE = /\{\{(q|raw|host|b64|b64host|asn|hex)\}\}/g;

  function fill(template, ioc) {
    return template.replace(TOKEN_RE, function (_, t) {
      switch (t) {
        case 'q': return encodeURIComponent(ioc.clean);
        case 'raw': return encodeURIComponent(ioc.value);
        case 'host': return encodeURIComponent(ioc.host || ioc.clean);
        case 'b64': return b64(ioc.clean);
        case 'b64host': return b64(ioc.host || ioc.clean);
        case 'asn': return (ioc.value.match(/\d+/) || [''])[0];
        case 'hex': return hex(ioc.host || ioc.clean);
      }
      return '';
    });
  }

  /**
   * Decide which indicator a tool should receive. Returns null when the tool cannot take it.
   * A URL or email is narrowed to its host when the tool only understands hosts, so pasting
   * https://evil.example/login into a domain-only tool queries "evil.example", not the whole URL.
   */
  function resolve(tool, ioc) {
    if (tool.ref || ioc.kind === 'empty') return ioc;
    var t = tool.types || [];
    if (t.indexOf('all') !== -1 || t.indexOf('any') !== -1 || t.indexOf(ioc.cls) !== -1) return ioc;
    if (ioc.cls === 'text' && t.indexOf('text') !== -1) return ioc;
    if ((ioc.cls === 'url' || ioc.cls === 'email') && ioc.host) {
      var h = parse(ioc.host);
      if (h.cls !== 'text' && t.indexOf(h.cls) !== -1) return h;
    }
    return null;
  }

  /** Does the tool accept this indicator? Reference-only tools (no query) always "apply". */
  function accepts(tool, ioc) { return resolve(tool, ioc) !== null; }

  function template(tool, ioc) {
    var r = tool.routes;
    if (r && ioc.kind !== 'empty') {
      if (r[ioc.kind]) return r[ioc.kind];
      if (r[ioc.cls]) return r[ioc.cls];
    }
    return tool.url;
  }

  /**
   * Build the outbound URL for a tool. Pure: never mutates tool data.
   * With an empty indicator the placeholders collapse, leaving the tool's search landing URL.
   */
  function buildUrl(tool, ioc) {
    ioc = ioc || parse('');
    if (tool.ref) return tool.url;
    if (ioc.kind === 'empty' && tool.home) return tool.home;
    var eff = resolve(tool, ioc) || ioc;
    return fill(template(tool, eff), eff);
  }

  var api = {
    refang: refang, parse: parse, buildUrl: buildUrl, accepts: accepts,
    isIPv4: isIPv4, isIPv6: isIPv6, b64: b64, stripScheme: stripScheme, hex: hex
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.OsintCore = api;
})(typeof self !== 'undefined' ? self : this);
