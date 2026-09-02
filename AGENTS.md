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
- Closest sibling project for architecture: `../orator-space` (D1, Crockford base32 ids).
- Closest sibling project for design language: `../pass.airat.top`.

## Structure
- Worker entry: `src/index.js` (routing, `/{id}` page, robots/sitemap, cron sweep).
- API handlers: `src/api.js`. D1 statements: `src/db.js`. Shared limits: `src/limits.js`.
- Identifiers: `src/ids.js` — UUIDv7 as 26-char Crockford base32.
- Schema: `migrations/`, applied with `wrangler d1 migrations apply DB`.
- Static UI: `public_html/` (`index.html` create, `view.html` reveal, `crypto.js` shared).

## The Invariant
The server never sees plaintext, the encryption key, or a passphrase. The key is generated
in the browser and lives in the URL fragment, which is never sent to the origin. Any change
that would put key material in a request body, a log line, or a D1 column is wrong, however
convenient it looks.

## AI Working Notes
- Revealing a secret is `POST /api/secrets/{id}/reveal` and nothing else. `GET /{id}` and
  `GET /api/secrets/{id}` must stay side-effect free so link previewers cannot burn a secret.
- `consumeSecret` increments the view counter inside the same UPDATE that reads the row.
  Splitting that into a read and a write reintroduces the double-read race.
- "Does not exist", "expired" and "already read" are one 404 with one message on purpose;
  telling them apart makes the endpoint an oracle for which ids were ever issued.
- Only `/` is indexable. Every other response carries `X-Robots-Tag: noindex` and is
  disallowed in `robots.txt`.
- Keep UI style consistent with the other AiratTop tools.

## Open Items
- `database_id` in `wrangler.jsonc` is a placeholder until `wrangler d1 create secret-airat`
  has been run.
- Favicons, `screenshot.png`, site-verification tags and the analytics counter are not in
  place yet; copy the pattern from `../pass.airat.top/public_html/index.html`.
