# Trace

A passive security review for the sites and codebases you build. Paste a link
and Trace reads the page, its response headers, cookies, CORS policy and
robots.txt. Or upload a project and Trace reads the source in the browser.
Every finding comes with evidence, the attacks it enables, and the fix.

## Run it

```sh
bun install
bun run dev        # http://localhost:5189 (Vite + the Worker in workerd)
bun run build      # dist/client (assets) + dist/trace/index.js (Worker)
bun run typecheck
bun run test
```

Routes: `/` landing, `/scan` the scanner (`?url=…` runs a scan, `?mode=upload`
opens the upload tab), `/attacks` the attack library, `/api/health`, and a 404
for anything else.

## How a scan works

**A link** is scanned by the Worker at `POST /api/scan-url`:

1. The URL is validated. Private, loopback, link-local and single-label hosts
   are refused, as are URLs with embedded credentials.
2. The page is requested with `redirect: 'manual'`, following up to four
   redirects so the chain can be reported. 9s timeout, 600 KB of HTML.
3. Response headers, `Set-Cookie` values and the HTML are collected, plus
   `robots.txt`.
4. One CORS probe is sent with a made-up `Origin`. If the server reflects it
   with `Access-Control-Allow-Credentials: true`, that is a critical finding.
5. `auditSite()` in `src/lib/audit.ts` runs the rules and returns findings,
   checks, a 0–100 score and a grade.

No payloads, no crawling, no path guessing. A small per-IP rate limit (12 per
minute, per isolate) keeps the endpoint usable.

**An upload** never leaves the browser. `src/lib/zip.ts` reads plain text files
and zips (central directory + `DecompressionStream('deflate-raw')`), skipping
`node_modules`, build output, lockfiles, binaries and anything over 1.5 MB.
`auditSource()` then scans line by line and masks secret values in the report.

## Where things live

- `src/lib/audit.ts` — types, both auditors, scoring, the check catalog.
- `src/lib/attacks.ts` — the 13 attack classes, each with steps, impact,
  defences and an OWASP link. Findings reference these ids, `/attacks` renders
  the same data.
- `src/lib/zip.ts` — browser-side file and zip reading.
- `src/worker/index.ts` — URL validation, SSRF guards, rate limit, fetch and
  the scan endpoint.
- `src/scan/` — `ScanPage` (form + orchestration), `Uploader`, `Results`
  (score, findings, attack mapping, checks, response details), `severity`.
- `src/sections/` — `Landing` (+ `SiteNav`/`SiteFooter`), `ScanMock`,
  `Attacks`, `NotFound`.
- `src/data.ts` — landing copy. `src/components/` is the design system
  (hairline borders, square corners, tokens in `src/styles.css`).

## The report

The results page shows the overall score and grade, a **score per area**
(Transport, Headers, Cookies, CORS, Content, Forms, Disclosure for a site;
Secrets, Injection, XSS, Crypto, Session, CORS, Transport, Config, Redirects,
Files, Supply chain, Disclosure for source), the full **attack matrix** — all
13 attack classes marked exposed or “no evidence” — every finding with
evidence and fix, the check list, and the raw response.

**Download report** writes a self-contained HTML file:
`trace-report-<host>-<date>.html`. No scripts, no external assets, everything
escaped; open it anywhere or print it to PDF. The same score, area table,
attack matrix, findings, exposed-attack defences and checks are inside.

## Checks

Site: HTTPS, HSTS, CSP (missing and permissive), clickjacking, `nosniff`,
referrer policy, permissions policy, COOP, CORP, legacy `X-XSS-Protection`,
version banners, CMS generator tags, cookie flags, CORS, mixed content,
insecure form actions and password fields, CSRF tokens on POST forms,
unsandboxed third-party iframes, third-party script integrity,
`target="_blank"`, secrets in HTML, stack traces on error pages, source maps,
robots.txt paths.

Source: hardcoded credentials, committed `.env` files, `eval`/`new Function`,
raw HTML sinks, concatenated SQL, plain-HTTP endpoints, disabled TLS
verification, MD5/SHA-1 password hashing, tokens in localStorage, wildcard and
reflected CORS, unverified `postMessage` / JWT, unsafe deserialisation, debug
mode, unvalidated redirects, path traversal, shell calls, unpinned
dependencies, published source maps.

## Limits

This is a first pass, not a penetration test: it does not run the app, send
exploit payloads, crawl, or check the TLS certificate, DNS or dependency CVEs.
Pattern rules are heuristics and can flag sample code. Scan only what you own
or have written permission to test.

## Deploy

`bun run build` writes `dist/client` and `dist/trace/index.js`;
`deploy.json` points a Worker deployment at both. Theme preference is stored
under `trace:theme`.
