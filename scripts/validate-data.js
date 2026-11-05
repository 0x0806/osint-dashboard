#!/usr/bin/env node
/* Validates data/tools.js: schema, unique ids, https-only URLs, valid placeholders, route keys.
 * Exit code 1 on any error so CI blocks bad catalogue changes. */
'use strict';
const path = require('path');
const DATA = require(path.join(__dirname, '..', 'data', 'tools.js'));

const TYPES = new Set(['ip', 'domain', 'url', 'email', 'hash', 'cve', 'asn', 'cidr', 'text', 'all', 'any']);
const ROUTE_KEYS = new Set(['ipv4', 'ipv6', 'cidr', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'sha512', 'ip', 'hash', 'cve', 'asn', 'text']);
const OPSEC = new Set(['active', 'submit']);
const TOKENS = /\{\{(\w+)\}\}/g;
const KNOWN_TOKENS = new Set(['q', 'raw', 'host', 'b64', 'b64host', 'asn', 'hex']);

const errors = [];
const err = (id, msg) => errors.push(`${id}: ${msg}`);

const cats = new Set();
for (const c of DATA.categories) {
  if (!c.id || !c.title || !c.group) err(`category ${c.id}`, 'needs id, title and group');
  if (cats.has(c.id)) err(`category ${c.id}`, 'duplicate category id');
  cats.add(c.id);
}

const ids = new Set();
const urls = new Map();
function checkUrl(id, label, u, ref) {
  if (typeof u !== 'string' || !u) return err(id, `${label} missing`);
  if (!/^https:\/\/[^\s/]+/.test(u)) err(id, `${label} must be an absolute https:// URL: ${u}`);
  if (/\s/.test(u)) err(id, `${label} contains whitespace: "${u}"`);
  let m; TOKENS.lastIndex = 0;
  let n = 0;
  while ((m = TOKENS.exec(u))) { n++; if (!KNOWN_TOKENS.has(m[1])) err(id, `${label} uses unknown placeholder {{${m[1]}}}`); }
  if (ref && n) err(id, `reference tools must not use placeholders (${label})`);
  if (!ref && !n && label === 'url') err(id, 'searchable tool needs a {{placeholder}} in url (or set "ref": true)');
}
for (const t of DATA.tools) {
  const id = t.id || '(no id)';
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(t.id || '')) err(id, 'id must be lowercase kebab-case');
  if (ids.has(t.id)) err(id, 'duplicate id');
  ids.add(t.id);
  if (!t.name || t.name !== t.name.trim()) err(id, 'name missing or has surrounding whitespace');
  if (!t.desc || t.desc.length < 8) err(id, 'desc missing or too short');
  if (!cats.has(t.cat)) err(id, `unknown category "${t.cat}"`);
  if (!Array.isArray(t.types) || !t.types.length) err(id, 'types must be a non-empty array');
  else t.types.forEach((x) => { if (!TYPES.has(x)) err(id, `unknown type "${x}"`); });
  if (t.opsec !== undefined && !OPSEC.has(t.opsec)) err(id, `opsec must be one of ${[...OPSEC]} (omit for passive)`);
  checkUrl(id, 'url', t.url, !!t.ref);
  if (t.home !== undefined) { checkUrl(id, 'home', t.home, true); if (t.ref) err(id, 'reference tools do not need a home URL'); }
  if (t.ref && t.routes) err(id, 'reference tools cannot have routes');
  if (t.ref && (t.types.length !== 1 || t.types[0] !== 'any')) err(id, 'reference tools must use types ["any"]');
  if (!t.ref && t.types && t.types.includes('any')) err(id, '"any" is only for reference tools; use "all" for free-text search engines');
  for (const [k, v] of Object.entries(t.routes || {})) {
    if (!ROUTE_KEYS.has(k)) err(id, `unknown route key "${k}"`);
    checkUrl(id, `route ${k}`, v, false);
  }
  const sig = `${t.ref ? 'R' : 'Q'}:${t.url}`;
  if (urls.has(sig)) err(id, `same URL as ${urls.get(sig)} (merge them)`);
  urls.set(sig, id);
  for (const a of t.aliases || []) if (typeof a !== 'string') err(id, 'aliases must be strings');
}
for (const f of DATA.defaultFavorites) if (!ids.has(f)) err('defaultFavorites', `unknown id ${f}`);
for (const c of DATA.categories) if (!DATA.tools.some((t) => t.cat === c.id)) err(`category ${c.id}`, 'has no tools');

if (errors.length) {
  console.error(`✗ ${errors.length} problem(s) in data/tools.js\n` + errors.map((e) => '  - ' + e).join('\n'));
  process.exit(1);
}
console.log(`✓ data/tools.js OK: ${DATA.tools.length} tools, ${DATA.categories.length} categories`);
