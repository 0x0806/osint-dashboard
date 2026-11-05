# Contributing

The dashboard is a zero-build static site. Almost every contribution is a change to **`data/tools.js`**.

```bash
npm run validate   # schema, unique ids, https-only, placeholders, routes
npm test           # indicator detection + URL building for every tool
npm run serve      # http://localhost:8080
npm run check-links  # best-effort liveness (bot-blocked sites are "inconclusive", never "dead")
```
Node 18+ is the only requirement; there are no dependencies to install.

## Adding a tool
Add one object to the `tools` array in `data/tools.js`:

```js
{"id":"example-lookup","name":"Example Lookup","cat":"ip","desc":"One sentence on what it tells an analyst",
 "url":"https://example.com/ip/{{q}}","types":["ip"]}
```

| Field | Rules |
|---|---|
| `id` | Unique, lowercase kebab-case. **Never rename an id**: favorites are stored by id. |
| `cat` | One of the category ids at the top of the file. |
| `url` | Absolute `https://`. Use `{{q}}` where the indicator goes. Tools with no query input set `"ref": true` and `"types": ["any"]` and use a plain URL. |
| `types` | What the tool accepts: `ip domain url email hash cve asn cidr text`, or `all` for free-text search engines. |
| `routes` | Optional. Different URL per indicator kind (`ipv4 ipv6 cidr domain url email md5 sha1 sha256 sha512`) or class (`ip hash ...`), e.g. host page vs. search page. |
| `opsec` | Omit for passive lookups. `"active"` if the vendor will scan/contact the target. `"submit"` if input becomes public. |
| `auth` | `true` if an account is usually needed to see results. |
| `aliases` | Old display names, used to migrate users' saved favorites after a rename. |

Placeholders: `{{q}}` (scheme and trailing slash stripped, URL-encoded), `{{raw}}` (full refanged value), `{{host}}`,
`{{b64}}`, `{{b64host}}`, `{{asn}}`, `{{hex}}`.

## Ground rules
- Only add tools you have opened and checked. Describe them honestly, including whether they touch the target.
- No trackers, URL shorteners or affiliate links. No tools whose main purpose is attacking or doxxing private individuals.
- No new runtime dependencies, external fonts or inline scripts/styles: the CSP will block them.
- Add or adjust a test in `tests/core.test.js` when you add a `routes` entry.
