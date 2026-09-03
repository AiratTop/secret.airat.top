# AGENTS.md

## Purpose
Public one-time secret sharing service (`secret.airat.top`). A secret is encrypted in the
browser, shared as a link, and destroyed after it is read or when its timer runs out.

## Repository Role
- Category: `*.airat.top` (public tool/service).
- Deployment platform: Cloudflare Workers with a D1 database and static assets.
- Deployment configuration: `wrangler.jsonc`.
- Deployment trigger: GitHub Actions (`.github/workflows/deploy.yml`), not the Cloudflare
  Git integration — Workers Builds does not apply D1 migrations. It runs the tests and the
  typecheck itself before touching Cloudflare, and is the only gate on a push to `main`.
  `.github/workflows/ci.yml` runs the same checks on pull requests and holds no
  credential, which is what makes it safe on an untrusted contribution and the right check
  to require once `main` is protected. Its job is named `ci` because that is the context
  the branch ruleset requires; renaming the job silently breaks every pull request, which
  then waits forever on a check that will never report.
- Custom domain: attached in the Cloudflare dashboard, not declared in `wrangler.jsonc`,
  as in every other project here. This keeps the CI token to Workers Scripts and D1, with
  no zone-level write access.
- Closest sibling project for architecture: `../orator-space` (D1, Crockford base32 ids).
- Closest sibling project for design language: `../pass.airat.top`.

## Structure
- Worker entry: `src/index.js` — routing, the `/{id}` page, robots/sitemap, cron sweep.
- `src/api.js` JSON handlers and input validation; `src/db.js` every D1 statement;
  `src/http.js` response helpers that put `noindex` and `no-store` on by default;
  `src/limits.js` the numbers both the client and the server validate against.
- Identifiers: `src/ids.js` — UUIDv7 as 26-char Crockford base32.
- Schema: `migrations/`, applied with `wrangler d1 migrations apply DB`.
- Static UI: `public_html/` — `index.html` + `app.js` create, `view.html` + `view.js`
  reveal, `crypto.js` the encryption both share, `format.js` the date format both share.
- Tests: `test/`, run with `npm test` — vitest in `workerd` against a real local D1, with
  the real `migrations/` applied. CI runs them before it touches Cloudflare.
- Community docs: `README.md`, `SECURITY.md`, `.github/CONTRIBUTING.md`,
  `.github/CODE_OF_CONDUCT.md`, `THIRD_PARTY_NOTICES.md`.

## API Summary
- Live endpoint: `https://secret.airat.top`.
- Status page: `https://status.airat.top`.
- `POST /api/secrets` store ciphertext; `GET /api/secrets/{id}` metadata, side-effect free;
  `POST /api/secrets/{id}/reveal` consume a view; `DELETE /api/secrets/{id}` needs the burn
  token; `GET /api/config` limits; `GET /health` liveness including a D1 round trip.
- No key and no account. Rate limited per address: 10 creates a minute, 60 of everything
  else. Bodies capped at 128 KB and must be `application/json`. Every response is JSON,
  `no-store` and `noindex`.
- The API cannot produce a usable link on its own: the caller encrypts, and the key goes
  in the fragment client-side. `public_html/crypto.js` is the reference implementation.
- Documented with worked examples in `README.md`; the request and response bodies there
  were captured from a real run, so keep them that way rather than writing them by hand.

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
- A view is spent only when the caller proves it holds the right key. The client sends a
  verifier (SHA-256 over a context string and the derived key); `consumeSecret` matches on
  it inside the same UPDATE, so a wrong passphrase or a truncated link changes no row.
  Checked only when the stored verifier is non-null, so secrets from before `0002` still
  open. `/reveal` answering 403 does reveal that an id is live — no new leak, because
  `GET /api/secrets/{id}` answers that openly already.
- "Does not exist", "expired" and "already read" are one 404 with one message on purpose;
  telling them apart makes the endpoint an oracle for which ids were ever issued.
- Only `/` is indexable. Every other response carries `X-Robots-Tag: noindex` and is
  disallowed in `robots.txt`.
- `/health` (`src/health.js`) sits ahead of the rate limiter deliberately — a status
  checker that gets a 429 reports an outage that is not happening — so it must not turn
  request volume into database load. It caches for ten seconds *and* single-flights: a
  cache alone is filled only after the query returns, so concurrent probes all miss it and
  each start a query. The cache is per isolate, so this bounds the load rather than
  globally limiting it.
- `verifier` is required on create. The column is nullable only for rows written before
  it existed; accepting a create without one would quietly reintroduce the bug where a
  failed attempt burns a view.
- Rate limiting lives in `enforceRateLimit` and counts in a Durable Object
  (`src/rate-limiter.js`), one per caller, with separate keys for writes and reads so a
  flood of creates cannot lock a recipient out of a secret about to expire. Fixed
  calendar windows, so ten requests at the end of one window and ten at the start of the
  next are both allowed — exact within a window, not a rolling limiter. **Not**
  Cloudflare's rate limit binding: it does enforce, but permissively by design — measured
  on the deployed Worker at a limit of 3/minute, 23 of 39 consecutive calls under one key
  were allowed before it started refusing, because the count propagates after the burst
  that a flood consists of. Cheaper than a Durable Object and the right choice where an
  approximate ceiling suffices; here the number needs to be real. Every
  `/api/` path goes through the limiter, `/api/config` included; it used to be answered
  ahead of the check and was therefore free to hammer. Tests give every request its own
  address so the limiter does not make the suite order-dependent.
- Request bodies are capped in `readJson` before parsing, by declared length and again
  while reading, because `request.json()` buffers everything first.
- `npm run typecheck` regenerates `worker-configuration.d.ts` with `wrangler types` and
  then runs `tsc`. That file is generated from `wrangler.jsonc` and is not committed, so
  the binding types cannot drift from the bindings that deploy. `checkJs` is on with
  `noImplicitAny` off, which is a real but partial check: it catches a property typo on a
  typed value and a union read without narrowing, and it does not catch misuse through an
  unannotated parameter, because that parameter is `any`. `app.js` and `view.js` are out
  of the program entirely — they need `lib: ["dom"]`, which collides with the Workers
  types; `test/routing.test.ts` covers what they mostly get wrong, which is element ids.
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

This means a privacy property of the project rests on a zone-level toggle rather than on
anything in this repository. If that setting were turned off, both pages would start
making requests to Google on load, including the page whose URL carries the decryption key.

**Self-hosting the fonts was considered and declined (2026-09-03).** Shipping `.woff2`
files here would move the guarantee into the repository, at the cost of a few hundred
kilobytes of binaries, a divergence from the sibling tools, and an ongoing thing to keep
updated. Cloudflare Fonts already delivers the outcome, the toggle is owned by the same
person who owns this project, and the risk of it being switched off unnoticed is not worth
that maintenance. Do not reopen this without a new reason — a fresh contributor proposing
self-hosted fonts should be pointed here.
