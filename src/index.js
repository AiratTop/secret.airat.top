/**
 * secret.airat.top — share a secret through a link that destroys itself.
 *
 * The design in one paragraph: the browser encrypts with AES-GCM, puts the key in the URL
 * fragment, and sends only the ciphertext here. A fragment is never transmitted to the
 * origin, so this Worker, its D1 database, its logs and its backups hold material that
 * cannot be decrypted by whoever holds them. Losing the link loses the secret, which is
 * the intended trade.
 *
 * Routes:
 *   /                       the create page (static)
 *   /{id}                   the view page (static shell; the ciphertext arrives by fetch)
 *   /api/...                see api.js
 *   /health                 liveness, including a D1 round trip
 *   everything else         static assets, then the asset server's own 404
 */

import { routeApi } from "./api.js";
import { isSecretId } from "./ids.js";
import { deleteExpired } from "./db.js";
import { SWEEP_BATCH, SWEEP_MAX_BATCHES, RATE_LIMITS } from "./limits.js";
import { json, text, error, withSecurityHeaders, withPageHeaders } from "./http.js";
import { checkHealth } from "./health.js";
import { TTL_OPTIONS, MAX_CIPHERTEXT_BYTES, MAX_VIEWS_LIMIT, DEFAULT_TTL, DEFAULT_MAX_VIEWS } from "./limits.js";

/** Serves a file out of `public_html` under a different path than it lives at. */
function serveAsset(request, env, assetPath) {
  const url = new URL(request.url);
  url.pathname = assetPath;
  return env.ASSETS.fetch(new Request(url, request));
}

/**
 * Per-address flood protection on the API surface.
 *
 * Writing and reading are counted separately, under different keys: a create is the
 * expensive act and the one that can fill a database, while a recipient reloading a page
 * must not be locked out of a secret that is about to burn.
 *
 * The binding is absent in the local dev server, where a Durable Object needs no
 * simulator but a developer serving themselves needs no limiter either. A missing binding
 * therefore means no limit, which is right for that one case and never true of a
 * deployment.
 */
async function enforceRateLimit(request, env, url) {
  if (!env.RATE_LIMITER) return null;

  /*
   * Classified by route, not by method. Creating is the only expensive, persistent act
   * here; revealing is a POST because it has a side effect, and metering it as a write
   * meant that ten creations from an office locked everyone behind that address out of
   * opening a secret — the exact failure separate counters exist to prevent. Destroying
   * is a DELETE and frees space, so it belongs with the cheap operations too.
   */
  const writing = request.method === "POST" && url.pathname === "/api/secrets";
  const { limit, periodSeconds } = writing ? RATE_LIMITS.write : RATE_LIMITS.read;

  // Cloudflare sets this at the edge and overwrites whatever the client sent, so it is
  // the one address a caller cannot choose for themselves.
  const address = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const key = `${writing ? "write" : "read"}:${address}`;

  const counter = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(key));
  const { allowed, retryAfter } = await (
    await counter.fetch("https://rate-limiter/count", {
      method: "POST",
      body: JSON.stringify({ limit, periodSeconds })
    })
  ).json();

  if (allowed) return null;

  return json(
    { error: "Too many requests. Try again shortly.", code: "rate_limited" },
    429,
    { "Retry-After": String(retryAfter) }
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/health") {
      const { payload, status } = await checkHealth(env);
      return json(payload, status);
    }

    // `html_handling` is off, so the asset server maps no path to a file on its own and
    // the root has to be spelled out. This is the one response with no `noindex` on it.
    if (path === "/" || path === "/index.html") {
      return withPageHeaders(await serveAsset(request, env, "/index.html"));
    }

    if (path.startsWith("/api/")) {
      const limited = await enforceRateLimit(request, env, url);
      if (limited) return limited;

      // The client reads its own validation rules from the server, so the form and the
      // API cannot disagree about what is allowed. Inside the limiter rather than ahead
      // of it: an endpoint answered before the check is an endpoint that can be hammered
      // for free.
      if (path === "/api/config") {
        return json({
          ttlOptions: TTL_OPTIONS,
          defaultTtl: DEFAULT_TTL,
          defaultMaxViews: DEFAULT_MAX_VIEWS,
          maxViews: MAX_VIEWS_LIMIT,
          maxCiphertextBytes: MAX_CIPHERTEXT_BYTES
        });
      }

      const response = routeApi(request, env, url);
      if (response) return response;
      return error("Unknown endpoint.", 404);
    }

    // `/{id}` — an id-shaped path is the view page, served as the same static shell for
    // every secret. Nothing about the secret is rendered server-side, so this response is
    // identical whether the id is live or long gone; the page finds out by fetching, and a
    // link previewer that never runs the script learns nothing and burns nothing.
    const idCandidate = path.slice(1);
    if (idCandidate.length > 0 && !idCandidate.includes("/") && isSecretId(idCandidate.toUpperCase())) {
      // Crockford base32 is case-insensitive, but one secret should have one URL.
      if (idCandidate !== idCandidate.toUpperCase()) {
        return Response.redirect(`${url.origin}/${idCandidate.toUpperCase()}${url.search}`, 301);
      }
      const response = await serveAsset(request, env, "/view.html");
      return withSecurityHeaders(response);
    }

    // Only the landing page is indexable. Everything else — every `/{id}`, the view
    // shell, the API — is disallowed here and carries `X-Robots-Tag: noindex` in its
    // response, because a crawler that ignores one should still be told by the other.
    // The stylesheet and the modules stay allowed: a renderer blocked from them judges
    // the one page that *is* meant to rank as broken.
    if (path === "/robots.txt") {
      return text(
        [
          "User-agent: *",
          "Allow: /$",
          "Allow: /styles.css",
          "Allow: /app.js",
          "Allow: /crypto.js",
          "Allow: /format.js",
          "Allow: /site.webmanifest",
          // Google fetches the favicon with a crawler, so `Disallow: /` would otherwise
          // cost the landing page its icon in search results.
          "Allow: /favicon.ico",
          "Allow: /favicon-16x16.png",
          "Allow: /favicon-32x32.png",
          "Allow: /apple-touch-icon.png",
          "Allow: /android-chrome-192x192.png",
          "Allow: /android-chrome-512x512.png",
          "Allow: /screenshot.png",
          "Disallow: /",
          "",
          `Sitemap: https://${env.SITE_HOST}/sitemap.xml`,
          ""
        ].join("\n")
      );
    }

    if (path === "/sitemap.xml") {
      // Built through the helper rather than a bare Response, which is how this one
      // answer came to be the only HTTPS response on the site without HSTS on it.
      return text(
        `<?xml version="1.0" encoding="UTF-8"?>\n` +
          `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
          `<url><loc>https://${env.SITE_HOST}/</loc><changefreq>monthly</changefreq></url>` +
          `</urlset>\n`,
        200,
        { "Content-Type": "application/xml; charset=utf-8" }
      );
    }

    // Falls through to the static assets. Deliberately without the `noindex` header the
    // helpers in http.js add: `/` is the only page meant to be found in a search engine.
    return withPageHeaders(await env.ASSETS.fetch(request));
  },

  /**
   * Housekeeping. Expiry is enforced in every read query, so an expired secret is already
   * unreachable before this runs — the sweep is what keeps the table from growing without
   * bound, not what makes expiry work.
   */
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(sweep(env));
  }
};

/**
 * Deletes expired rows in bounded batches, stopping as soon as a batch comes back short.
 *
 * One unbounded DELETE is what stalls a D1 after an outage or a flood; one bounded batch
 * every fifteen minutes is too slow to catch up from either. A handful of bounded batches
 * is neither.
 */
async function sweep(env) {
  let total = 0;
  for (let batch = 0; batch < SWEEP_MAX_BATCHES; batch++) {
    const deleted = await deleteExpired(env.DB, Date.now(), SWEEP_BATCH);
    total += deleted;
    if (deleted < SWEEP_BATCH) break;
  }
  if (total > 0) console.log(`retention: deleted ${total} expired secrets`);
}

export { RateLimiter } from "./rate-limiter.js";
