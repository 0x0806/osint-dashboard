# OSINT Dashboard

An analyst console that turns **one indicator** into ready-to-open lookups across **273 OSINT and threat-intel tools**.
Paste an IP, domain, URL, email, hash, CVE or ASN; the dashboard recognises it, builds the correct URL for every tool, and
tells you which tools apply and what each one reveals about your investigation.

Zero build, zero dependencies, zero backend. It runs entirely in your browser and never transmits your indicator itself.

## Features

| | |
|---|---|
| **Indicator detection** | IPv4, IPv6, CIDR, domain (incl. IDN), URL, email, MD5/SHA-1/SHA-256/SHA-512, CVE, ASN. Anything else is treated as free text / username. |
| **Refang on paste** | `hxxps://evil[.]example[.]com`, `user[@]example(.)com`, `1[.]2[.]3[.]4` all just work. |
| **Indicator-aware links** | Per-tool routing: Shodan opens a host page for an IP but a search for a domain; VirusTotal opens the file/IP/domain page directly; a URL pasted into a domain-only tool is narrowed to its hostname. |
| **Applicability** | Tools that cannot take the current indicator are dimmed, or hidden with *Applies to indicator*. |
| **OPSEC labels** | **Active** = the vendor contacts the target (your interest may be visible). **Submits** = what you upload may become public. **Login** = needs an account. Filter to *Passive only* in one click. |
| **Favorites** | Star any tool, reorder with the arrows, then **Open favorites** (with a confirmation that lists active tools). Persisted locally. |
| **Navigation** | Grouped category sidebar with live counts, collapsible sections, text filter, mobile jump menu. |
| **Share / backup** | *Copy share link* (`?q=`), export/import settings as JSON, copy any tool's built URL. |
| **Accessibility** | Keyboard operable, visible focus, screen-reader labels and live regions, AA contrast in light and dark, `prefers-reduced-motion`, forced-colors and print styles. |
| **Keyboard** | `/` indicator, `f` filter, `t` theme, `o` open favorites, `?` help, `Esc` clear. |

## Privacy and operational security

- The page has **no analytics, cookies, trackers, external fonts or third-party scripts**. A strict Content-Security-Policy
  (`default-src 'none'; script-src 'self'; connect-src 'none'`) makes the browser enforce that.
- `Referrer-Policy: no-referrer` and `rel="noopener noreferrer"` stop the indicator leaking to a vendor via the `Referer` header.
- **Clicking a tool sends your indicator to that vendor.** That is the whole point, and also the risk: for sensitive
  investigations use *Passive only*, prefer vendors you trust, and use a research browser profile or VPN/egress you are comfortable attributing.
- "Recent indicators" is **off by default**; when enabled it is stored only in your browser and can be wiped in Settings.
- `?q=` share links contain the indicator in the URL (and therefore in browser history and any chat you paste it into).
- OPSEC labels are best-effort editorial judgments, not guarantees. Vendors change behaviour; verify before relying on them.

## Use it

Hosted via GitHub Pages, or locally:

```bash
git clone https://github.com/0x0806/osint-dashboard && cd osint-dashboard
python3 -m http.server 8080      # or just open index.html; it works from file:// too
```

Deep links: `index.html?q=8.8.8.8` (also accepts `?ip=`).

## Project layout

```
index.html          page shell (no inline script/style; CSP in <meta>)
assets/core.js      pure logic: refang, detection, routing, URL building (unit-tested)
assets/app.js       UI, state, persistence, accessibility
assets/styles.css   light/dark themes, responsive layout
data/tools.js       the catalogue: 273 tools, 24 categories (the file most PRs touch)
tests/              node:test suite     scripts/  validator + link checker
```

## Development

```bash
npm run validate     # catalogue schema, unique ids, https-only, placeholders
npm test             # detection + URL building for every tool and indicator type
npm run check-links  # best-effort liveness; 403/429 from bot-blocking vendors are "inconclusive", never "dead"
```
CI runs validation, the tests and a CSP guard (no inline code) on every push and PR; a weekly workflow runs the link check.
See [CONTRIBUTING.md](CONTRIBUTING.md) to add a tool, [SECURITY.md](SECURITY.md) to report a vulnerability, and
[docs/REVIEW.md](docs/REVIEW.md) for the engineering review, what changed from v2, and the roadmap.

## Upgrading from v2
Favorites you saved in the old build are migrated automatically (matched by tool name). Category drag-and-drop order was
dropped in favour of favorites, which were the only thing most people actually customised.

## License
MIT. See [LICENSE](LICENSE). Third-party tools linked here belong to their respective owners; listing is not endorsement.
