# Security policy

This is a static, client-side site: no server, no accounts, no cookies, no analytics.

## Reporting a vulnerability
Please use GitHub's **private vulnerability reporting** (Security tab > Report a vulnerability) rather than a public issue.
Useful reports include XSS, anything that sends an indicator to a host the user did not click, CSP bypasses, and
catalogue entries that point at a malicious or typosquatted domain.

## Design guarantees we defend
- A strict `Content-Security-Policy` (`default-src 'none'; script-src 'self'; connect-src 'none'`): no inline code, no remote code, no network requests from the page.
- `referrer: no-referrer` plus `rel="noopener noreferrer"` on every outbound link, so a vendor never learns the indicator from the `Referer` header.
- The page itself never transmits the indicator. It only builds links; the browser contacts a vendor when the user opens one.
- All DOM is built with `textContent`/`setAttribute`. Stored settings are validated against the catalogue before use.
- Catalogue URLs must be absolute `https://` and are checked in CI.

## Supported versions
Only the latest commit on `main` (the deployed site).
