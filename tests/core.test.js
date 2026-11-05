'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('../assets/core.js');
const DATA = require('../data/tools.js');
const tool = (id) => DATA.tools.find((t) => t.id === id);
const url = (id, input) => core.buildUrl(tool(id), core.parse(input));

test('refang handles common defanging styles', () => {
  assert.equal(core.refang('hxxps://evil[.]example[.]com/a'), 'https://evil.example.com/a');
  assert.equal(core.refang('user[@]example(.)com'), 'user@example.com');
  assert.equal(core.refang('1[.]2[.]3[.]4'), '1.2.3.4');
  assert.equal(core.refang('  <8.8.8.8>  '), '8.8.8.8');
  assert.equal(core.refang('hxxp[:]//a[dot]b'), 'http://a.b');
});

test('parse classifies indicators', () => {
  const k = (s) => core.parse(s).kind;
  assert.equal(k('8.8.8.8'), 'ipv4');
  assert.equal(k('256.1.1.1'), 'text');
  assert.equal(k('1.2'), 'text');
  assert.equal(k('2001:4860:4860::8888'), 'ipv6');
  assert.equal(k('::1'), 'ipv6');
  assert.equal(k('::ffff:1.2.3.4'), 'ipv6');
  assert.equal(k('1:2:3:4:5:6:7:8:9'), 'text');
  assert.equal(k('10.0.0.0/8'), 'cidr');
  assert.equal(k('10.0.0.0/33'), 'text');
  assert.equal(k('example.com'), 'domain');
  assert.equal(k('münchen.de'), 'domain');
  assert.equal(k('xn--mnchen-3ya.de'), 'domain');
  assert.equal(k('https://example.com/path?q=1'), 'url');
  assert.equal(k('example.com/login'), 'url');
  assert.equal(k('a@b.example'), 'email');
  assert.equal(k('d41d8cd98f00b204e9800998ecf8427e'), 'md5');
  assert.equal(k('DA39A3EE5E6B4B0D3255BFEF95601890AFD80709'), 'sha1');
  assert.equal(k('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), 'sha256');
  assert.equal(k('cve-2024-3094'), 'cve');
  assert.equal(k('as15169'), 'asn');
  assert.equal(k('some_username'), 'text');
  assert.equal(k(''), 'empty');
  assert.equal(core.parse('CVE-2024-3094').value, 'CVE-2024-3094');
  assert.equal(core.parse('as15169').value, 'AS15169');
  assert.equal(core.parse('ABCDEF0123456789ABCDEF0123456789').value, 'abcdef0123456789abcdef0123456789');
});

test('parse derives host and cleaned value', () => {
  const p = core.parse('https://user:pw@Example.com:8443/a/b?c=d#e');
  assert.equal(p.host, 'Example.com');
  assert.equal(core.parse('https://example.com/').clean, 'example.com');
  assert.equal(core.parse('a@mail.example.org').host, 'mail.example.org');
  assert.equal(core.parse('[2001:db8::1]').kind, 'ipv6');
});

test('b64 and hex are UTF-8 safe (btoa alone throws on non-Latin-1)', () => {
  assert.equal(core.b64('münchen.de'), Buffer.from('münchen.de').toString('base64'));
  assert.doesNotThrow(() => core.b64('日本語.jp'));
  assert.equal(core.hex('a.b'), '612e62');
});

test('buildUrl never mutates catalogue data', () => {
  const before = JSON.stringify(DATA.tools);
  DATA.tools.forEach((t) => core.buildUrl(t, core.parse('8.8.8.8')));
  assert.equal(JSON.stringify(DATA.tools), before);
});

test('buildUrl routes by indicator kind', () => {
  assert.equal(url('shodan', '8.8.8.8'), 'https://www.shodan.io/host/8.8.8.8');
  assert.equal(url('shodan', 'example.com'), 'https://www.shodan.io/search?query=example.com');
  assert.equal(url('greynoise', '8.8.8.8'), 'https://viz.greynoise.io/ip/8.8.8.8');
  assert.equal(url('greynoise', 'example.com'), 'https://viz.greynoise.io/query/example.com');
  assert.equal(url('silent-push', '8.8.8.8'), 'https://explore.silentpush.com/enrichment/ipv4/8.8.8.8');
  assert.equal(url('silent-push', '2001:db8::1'), 'https://explore.silentpush.com/enrichment/ipv6/2001%3Adb8%3A%3A1');
  assert.equal(url('metadefender', 'example.com'), 'https://metadefender.opswat.com/results/domain/ZXhhbXBsZS5jb20=');
  assert.equal(url('metadefender', 'https://example.com/x'), 'https://metadefender.opswat.com/results/domain/ZXhhbXBsZS5jb20=');
  assert.equal(url('metadefender', '8.8.8.8'), 'https://metadefender.opswat.com/results/ip/OC44LjguOA==');
  assert.equal(url('ibm-x-force', '8.8.8.8'), 'https://exchange.xforce.ibmcloud.com/ip/8.8.8.8');
  assert.equal(url('threat-miner', 'example.com'), 'https://www.threatminer.org/domain.php?q=example.com');
  assert.equal(url('fortiguard', '8.8.8.8'), 'https://www.fortiguard.com/threatintel-search');
  assert.equal(url('web-check', 'https://example.com/a'), 'https://web-check.xyz/check/https%3A%2F%2Fexample.com%2Fa');
  assert.equal(url('virustotal', 'd41d8cd98f00b204e9800998ecf8427e'), 'https://www.virustotal.com/gui/file/d41d8cd98f00b204e9800998ecf8427e');
  assert.equal(url('bgp-he', 'AS15169'), 'https://bgp.he.net/AS15169');
  assert.equal(url('nvd-nist', 'cve-2024-3094'), 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094');
});

test('URL tool inputs are encoded as a single path/query component', () => {
  assert.equal(url('urlscan', 'https://example.com/a?b=c&d=e'), 'https://urlscan.io/search/#example.com%2Fa%3Fb%3Dc%26d%3De');
  assert.equal(url('wayback-machine', 'hxxps://example[.]com/'), 'https://web.archive.org/web/*/example.com');
});

test('URLs and emails are narrowed to their host for host-only tools', () => {
  assert.equal(url('crtsh', 'https://evil.example.com/login?x=1'), 'https://crt.sh/?q=evil.example.com');
  assert.equal(url('crtsh', 'user@mail.example.org'), 'https://crt.sh/?q=mail.example.org');
  assert.equal(url('shodan', 'http://8.8.8.8:8080/admin'), 'https://www.shodan.io/host/8.8.8.8');
  assert.equal(url('abuseipdb', 'http://8.8.8.8/x'), 'https://www.abuseipdb.com/check/8.8.8.8');
  assert.equal(url('urlscan', 'https://example.com/a'), 'https://urlscan.io/search/#example.com%2Fa', 'tools that accept url keep the full URL');
});

test('empty indicator yields each tool\'s landing URL (placeholders collapse)', () => {
  assert.equal(url('urlscan', ''), 'https://urlscan.io/search/#');
  assert.equal(url('cyberchef', ''), 'https://gchq.github.io/CyberChef/');
  assert.equal(url('peeringdb', ''), 'https://www.peeringdb.com/', 'mid-path templates use their home URL');
  assert.equal(url('peeringdb', 'AS15169'), 'https://www.peeringdb.com/asn/15169');
});

test('accepts() gates tools by indicator class', () => {
  const ip = core.parse('8.8.8.8');
  assert.equal(core.accepts(tool('shodan'), ip), true);
  assert.equal(core.accepts(tool('nvd-nist'), ip), false);
  assert.equal(core.accepts(tool('cyberchef'), ip), true, 'reference tools always apply');
  assert.equal(core.accepts(tool('duckduckgo'), ip), true, '"all" tools take anything');
  assert.equal(core.accepts(tool('crtsh'), core.parse('user@example.com')), true, 'email -> domain tools');
  assert.equal(core.accepts(tool('whatsmyname'), core.parse('jdoe')), true);
  assert.equal(core.accepts(tool('whatsmyname'), ip), false);
});

test('catalogue sanity', () => {
  const ids = DATA.tools.map((t) => t.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(DATA.tools.length > 250);
  for (const f of DATA.defaultFavorites) assert.ok(ids.includes(f));
  // every searchable tool must produce a valid https URL for every indicator kind it claims to accept
  const samples = { ip: '8.8.8.8', domain: 'example.com', url: 'https://example.com/a', email: 'a@example.com', hash: 'd41d8cd98f00b204e9800998ecf8427e', cve: 'CVE-2024-3094', asn: 'AS15169', cidr: '10.0.0.0/8', text: 'jdoe' };
  for (const t of DATA.tools) {
    if (t.ref) continue;
    for (const ty of t.types) {
      if (!samples[ty]) continue;
      const u = core.buildUrl(t, core.parse(samples[ty]));
      assert.match(u, /^https:\/\//, `${t.id}/${ty}`);
      assert.doesNotMatch(u, /\{\{|\}\}/, `${t.id}/${ty} has an unreplaced placeholder`);
      assert.doesNotThrow(() => new URL(u), `${t.id}/${ty}`);
    }
  }
});
