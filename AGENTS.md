# AGENTS.md

## Purpose
Public one-time secret sharing service (`secret.airat.top`). A secret is encrypted in the
browser, shared as a link, and destroyed after it is read or when its timer runs out.

## Repository Role
- Category: `*.airat.top` (public tool/service).
- Deployment platform: Cloudflare Workers with a D1 database and static assets.
- Deployment configuration: `wrangler.jsonc`.
- Deployment trigger: GitHub Actions (`.github/workflows/deploy.yml`), not the Cloudflare
  Git integration — Workers Builds does not apply D1 migrations.
- Custom domain: attached in the Cloudflare dashboard, not declared in `wrangler.jsonc`,
  as in every other project here. This keeps the CI token to Workers Scripts and D1, with
  no zone-level write access.
- Closest sibling project for architecture: `../orator-space` (D1, Crockford base32 ids).
- Closest sibling project for design language: `../pass.airat.top`.

## Structure
- Worker entry: `src/index.js` (routing, `/{id}` page, robots/sitemap, cron sweep).
- API handlers: `src/api.js`. D1 statements: `src/db.js`. Shared limits: `src/limits.js`.
- Identifiers: `src/ids.js` — UUIDv7 as 26-char Crockford base32.
- Schema: `migrations/`, applied with `wrangler d1 migrations apply DB`.
- Static UI: `public_html/` (`index.html` create, `view.html` reveal, `crypto.js` shared).
- Tests: `test/`, run with `npm test` — vitest in `workerd` against a real local D1, with
  the real `migrations/` applied. CI runs them before it touches Cloudflare.

## The Invariant
The server never sees plaintext, the encryption key, or a passphrase. The key is generated
in the browser and lives in the URL fragment, which is never sent to the origin. Any change
that would put key material in a request body, a log line, or a D1 column is wrong, however
convenient it looks.

## AI Working Notes
- Revealing a secret is `POST /api/secrets/{id}/reveal` and nothing else. `GET /{id}` and
  `GET /api/secrets/{id}` must stay side-effect free so link previewers cannot burn a secret.
- `consumeSecret` increments the view counter inside the same UPDATE that reads the row.
  Splitting that into a read and a write reintroduces the double-read race; the two
  concurrency tests in `test/api.test.ts` fail when it is, which was verified by breaking
  it on purpose rather than assumed.
- "Does not exist", "expired" and "already read" are one 404 with one message on purpose;
  telling them apart makes the endpoint an oracle for which ids were ever issued.
- Only `/` is indexable. Every other response carries `X-Robots-Tag: noindex` and is
  disallowed in `robots.txt`.
- Keep UI style consistent with the other AiratTop tools.

## Analytics and Third-Party Scripts
This project carries no analytics and no third-party script, unlike the other AiratTop
tools which share the GA counter. Do not add one back. On `/{id}#{key}` the fragment is
the decryption key, and `gtag` reports `document.location.href` as `page_location` — a
counter there would send every secret's key to Google. Running one on the landing page
only was considered and rejected: for a secret-sharing tool, "no third-party scripts
anywhere" is worth more than pageviews, and Cloudflare counts requests server-side without
a script and without ever seeing a fragment.

## Fonts
`index.html` and `view.html` link Space Grotesk and JetBrains Mono from Google Fonts, the
same as the other AiratTop tools. In production those links never reach Google: the
airat.top zone has Cloudflare Fonts enabled, and Cloudflare rewrites them into
`@font-face` rules served from `/cf-fonts/...` on this origin. Verified against the live
site — the delivered HTML contains no fonts.googleapis.com reference at all.

Worth knowing because it means a privacy property of this project rests on a zone-level
toggle rather than on anything in this repository. If that setting is ever turned off, both
pages start making requests to Google on load, including the page whose URL carries the
decryption key. See Open Items.

## Open Items
- Decide whether to self-host the two fonts as `.woff2` files in `public_html`. Today
  Cloudflare Fonts makes the site third-party-free in practice, but only while that zone
  setting stays on; self-hosting would make it a property of the repository instead. The
  cost is a few hundred kilobytes of binaries and a divergence from the sibling projects.
