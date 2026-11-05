#!/usr/bin/env node
/* Best-effort link checker (Node 18+). Run manually or from the scheduled workflow.
 * Many security sites block bots (403/429/503): those are reported as "inconclusive", never as dead.
 * Only DNS failures, TLS failures, 404 and 410 are treated as broken. */
'use strict';
const path = require('path');
const DATA = require(path.join(__dirname, '..', 'data', 'tools.js'));
const core = require(path.join(__dirname, '..', 'assets', 'core.js'));

// Type-appropriate probes: asking an IP-only tool about "example.com" would 404 by design.
const SAMPLES = { ip: '8.8.8.8', domain: 'example.com', url: 'https://example.com/', email: 'test@example.com', hash: 'd41d8cd98f00b204e9800998ecf8427e', cve: 'CVE-2021-44228', asn: 'AS15169', cidr: '8.8.8.0/24', text: 'jdoe', all: 'example.com' };
const concurrency = 8;
const timeoutMs = 15000;
const jobs = [];
for (const t of DATA.tools) {
  jobs.push({ t, kind: 'landing', url: core.buildUrl(t, core.parse('')) });
  if (!t.ref) jobs.push({ t, kind: 'sample', url: core.buildUrl(t, core.parse(SAMPLES[t.types[0]] || 'example.com')) });
}
const broken = [], inconclusive = [];
let ok = 0;

async function check(job) {
  const { t, kind, url } = job;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'follow', signal: ctl.signal, headers: { 'user-agent': 'osint-dashboard-link-check/3 (+https://github.com/0x0806/osint-dashboard)' } });
    // A 404 on a *landing* page means the tool moved. A 404 on a sample lookup can simply mean "no data for that indicator".
    if ((res.status === 404 || res.status === 410) && kind === 'landing') broken.push(`${t.id}  ${res.status}  ${url}`);
    else if (res.status >= 400) inconclusive.push(`${t.id}  ${res.status}  ${kind}  ${url}`);
    else ok++;
  } catch (e) {
    const code = (e.cause && e.cause.code) || e.name;
    if (['ENOTFOUND', 'ECONNREFUSED', 'CERT_HAS_EXPIRED', 'ERR_TLS_CERT_ALTNAME_INVALID', 'DEPTH_ZERO_SELF_SIGNED_CERT'].includes(code)) broken.push(`${t.id}  ${code}  ${url}`);
    else inconclusive.push(`${t.id}  ${code}  ${kind}  ${url}`);
  } finally { clearTimeout(timer); }
}
const queue = jobs.slice();
async function worker() { while (queue.length) await check(queue.shift()); }

Promise.all(Array.from({ length: concurrency }, worker)).then(() => {
  console.log(`reachable: ${ok}   inconclusive (bot-blocked/timeouts): ${inconclusive.length}   broken: ${broken.length}`);
  if (inconclusive.length) console.log('\nINCONCLUSIVE\n' + inconclusive.join('\n'));
  if (broken.length) { console.log('\nBROKEN\n' + broken.join('\n')); process.exit(1); }
});
