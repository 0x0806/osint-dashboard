# Engineering review: v2 → v3

Scope: a full read of the v2 single-file `index.html` (≈2,100 lines: 770 CSS, 1,300 JS and data), a redesign, and an
enterprise-readiness pass. Everything below was verified by reading the code or by executing it; test names are in `tests/core.test.js`.

## 1. Defects found in v2 and how they were fixed

| # | Severity | Defect | Fix in v3 |
|---|---|---|---|
| 1 | **High** | Tools were identified by display name. Four names appear twice (*Virus Total*, *Hybrid Analysis*, *OSINT Framework*, *Perplexity*). The saved-order lookup keeps the last duplicate, so after any drag-and-reload the **Favorites "Virus Total" silently became the file-upload page and stopped receiving the query**. | Every tool has a stable `id`; favorites are stored by id; duplicates merged or disambiguated (`virustotal` vs `virustotal-upload`). |
| 2 | **High** | `updateLinks` **overwrote `url` on the shared catalogue objects**. `openFavorites` then reused those mutated URLs, so it opened with the *previous* query if the box changed without pressing ADD, used `.replace` (first match only), and ignored per-tool special cases (Shodan host/search). | One pure `buildUrl(tool, ioc)` used by the card renderer, copy button and favorites opener. Test: *buildUrl never mutates catalogue data*. |
| 3 | **High** | **URL Scan (a default favorite) opened with no query**: its URL ends in `#`, and `openFavorites` only appended the query for URLs ending in `=` or `/`. | Placeholders (`{{q}}`) replace "append to the end" heuristics. |
| 4 | **High** | **Typing in the filter box could crash rendering**: the filter calls `t.desc.toLowerCase()` and *Any Run* has no `desc`. | Descriptions are required by the validator; filtering is null-safe. |
| 5 | **High** | `btoa(cleaned)` throws on any non-Latin-1 character (IDNs, emoji), aborting the whole search. | UTF-8 safe `b64()`. Test: *b64 and hex are UTF-8 safe*. |
| 6 | Med | Saving drag order while a filter was active persisted only the visible subset. | Drag ordering removed; favorites are an explicit list unaffected by filters. |
| 7 | Med | Names with leading spaces (`" Cursor"`, `" Void"`) never matched saved order after `trim()`. | Normalised names; migration indexes trimmed, lower-cased names and aliases. |
| 8 | Med | If the Sortable CDN failed (blocked network, offline), `Sortable.create` threw inside `renderCategory` and the **page rendered blank**. The CDN script also had no SRI. | No third-party code at all. |
| 9 | Med | The indicator leaked through the `Referer` header to every vendor (no `referrer` policy). | `no-referrer` meta + `rel="noopener noreferrer"`. |
| 10 | Med | IP detection `^[\d.]+$` accepted `1.2` / `...` and missed IPv6, sending both down the wrong route. | Strict IPv4/IPv6/CIDR validation with tests, including `::ffff:1.2.3.4` and rejection of `256.1.1.1`. |
| 11 | Med | URL input was inserted into path-style tools unencoded (`…/query/example.com/path?x=1`), turning the URL's own query string into the vendor's. | Everything is encoded as a single component; URLs narrow to hostname for host-only tools. |
| 12 | Low | Wayback URL hard-coded a 2025 timestamp; YARAify URL had a leading space; typo "Info is Beauy"; `replaceSpecialCharacters` defined twice and never used. | Fixed / removed. |
| 13 | Low | Theme not persisted and ignored `prefers-color-scheme`; toast inline styles overrode the theme and had no `aria-live`; focus outlines removed with no replacement; favorites arrow was a `<span onclick>` unreachable by keyboard; category names injected through `innerHTML`; footer had unclosed markup and Bootstrap classes with no Bootstrap, plus ~200 lines of dead newsletter/particle CSS. | Rebuilt: system/light/dark with persistence, live regions, visible focus, real buttons, DOM built via `textContent`, dead code deleted. |

## 2. What was added (enterprise-grade gaps)

- **Indicator intelligence**: type detection, refang, per-kind routing, applicability filtering.
- **OPSEC model**: passive / active / submits / login labels, a passive-only filter, and a confirmation before opening many tabs that lists active tools.
- **Catalogue integrity**: 273 tools with stable ids, aliases for migration, typed `routes`, and a validator (`npm run validate`) enforcing https-only URLs, unique ids, known placeholders and non-empty descriptions. 30 tools added and 3 verified-dead entries removed (see §5) (CVE/EPSS, BGP/ASN, code search, corporate/sanctions records, blockchain, InternetDB, Triage, etc.); 20+ reference-only entries upgraded to real indicator searches (NVD, CVE.org, ExploitDB, MalwareBazaar, ThreatFox, …).
- **Security posture**: strict CSP, no third-party code/fonts, no storage of indicators by default, settings validated on import and on load.
- **Quality gates**: 11 unit tests over detection/routing/every-tool URL generation, CI with a CSP guard, weekly link-check workflow, issue/PR templates, CONTRIBUTING and SECURITY.
- **UX/a11y**: sidebar navigation with live counts, collapsible sections, keyboard shortcuts, mobile layout, AA contrast, reduced-motion, forced-colors, print stylesheet.
- **Backwards compatibility**: saved v2 favorites are migrated by name (including the space-prefixed names).

Verification performed: the old URL builder was ported verbatim and diffed against `buildUrl` over 5 sample indicators × every legacy tool
(1,250 pairs). Every difference was intentional: new indicator-specific routes, URL/email narrowed to hostname for host-only tools, removed hard-coded year, encoding fixes. A scripted
Chromium session confirmed rendering, migration, persistence, filtering, dialogs, shortcuts, no horizontal scroll at 390px and a clean console.

## 3. Known limitations (be honest about these)

- **Catalogue links are not all freshly verified.** Existing entries were carried over; new ones follow each vendor's documented URL patterns but several vendors block bots, so automated checks can only prove "not obviously dead". Run `npm run check-links` and spot-check; expect some drift (vendors rename and retire pages constantly).
- **OPSEC labels are editorial.** `active`/`submit`/`auth` flags are a best-effort reading of each vendor's behaviour as of this release.
- **Vendor routes can change.** Deep links such as `/gui/ip-address/{ip}` are more brittle than a search box. The weekly link check and the issue template exist for this reason.
- **No drag-and-drop** any more. Reordering is via the favorite arrows (keyboard accessible).
- Single indicator at a time; no persistence of investigations.

## 4. Roadmap (prioritised, not built)

**P0: before calling this "operational"**
1. Run `check-links` in CI on a schedule and auto-open an issue on `broken` results (workflow exists; add the issue step).
2. Serve with real headers (GitHub Pages cannot): put it behind Cloudflare/Netlify to add `Content-Security-Policy` (so `frame-ancestors 'none'` works, which a `<meta>` CSP cannot express), `X-Content-Type-Options`, `Referrer-Policy`, and clickjacking protection.
3. Pin and review contributor PRs touching `data/tools.js` for typosquatted domains (CODEOWNERS + required review).

**P1: highest user value**
4. **Bulk mode**: paste a list of IOCs from a report, classify each, export a CSV/Markdown table of generated links, open selected sets.
5. **Investigation notes**: per-indicator checklist ("checked VT, Shodan, …") stored locally, exportable to Markdown for tickets.
6. **Custom tools**: let users add private/internal tools (SIEM, TIP, internal wiki) with the same `{{q}}` template syntax, kept in local storage.
7. **Playbooks**: ordered tool sets per indicator type ("Phishing URL triage", "Suspicious IP"), openable with one click.

**P2: platform**
8. **Optional self-hosted enrichment backend** (small service holding API keys for VirusTotal/Shodan/GreyNoise/AbuseIPDB) returning a unified verdict card. Keys must never ship in a static site. Needs auth, rate limiting, audit logging and an egress policy.
9. Browser E2E tests (Playwright) in CI; visual regression screenshots; axe-core accessibility run.
10. Installable PWA with a conservative service worker (precache shell only) for offline use.
11. Localisation, a command palette (`Ctrl+K`), and a browser-extension variant ("right-click an IOC → investigate").
12. Move the catalogue to JSON with a published JSON Schema and `tools.min.json` for other projects to consume.

## 5. Link audit (run against the live web)

`npm run check-links` probes every tool's landing URL and one type-appropriate sample lookup. Result on the final catalogue: **304 reachable, 89 inconclusive (403/429/timeouts from bot-blocking vendors, not counted as dead), 0 broken**.
Findings acted on: removed `threatbutt.com` and `cvesky.labs.greynoise.io` (no DNS records) and the Ruler Project Pages site (404 at its root); repointed Search Encrypt (invalid TLS on `www`, apex works) and the Intel Techniques podcast (page 404, site root works); added a `home` landing URL for tools whose placeholder sits mid-path (URLVoid, Sicehice, PeeringDB, NVD, …) so the no-indicator link never lands on a 404.
