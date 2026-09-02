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
import { json, text, error, withSecurityHeaders } from "./http.js";
import { TTL_OPTIONS, MAX_CIPHERTEXT_BYTES, MAX_VIEWS_LIMIT, DEFAULT_TTL, DEFAULT_MAX_VIEWS } from "./limits.js";

/** Serves a file out of `public_html` under a different path than it lives at. */
function serveAsset(request, env, assetPath) {
  const url = new URL(request.url);
  url.pathname = assetPath;
  return env.ASSETS.fetch(new Request(url, request));
}

async function handleHealth(env) {
  try {
    await env.DB.prepare("SELECT 1").first();
    return json({ status: "ok", database: "ok" });
  } catch {
    // 503 rather than 200-with-a-flag: a status checker should see this as down.
    return json({ status: "degraded", database: "unavailable" }, 503);
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/health") return handleHealth(env);

    // `html_handling` is off, so the asset server maps no path to a file on its own and
    // the root has to be spelled out. This is the one response with no `noindex` on it.
    if (path === "/" || path === "/index.html") return serveAsset(request, env, "/index.html");

    // The client reads its own validation rules from the server, so the form and the API
    // cannot disagree about what is allowed.
    if (path === "/api/config") {
      return json({
        ttlOptions: TTL_OPTIONS,
        defaultTtl: DEFAULT_TTL,
        defaultMaxViews: DEFAULT_MAX_VIEWS,
        maxViews: MAX_VIEWS_LIMIT,
        maxCiphertextBytes: MAX_CIPHERTEXT_BYTES
      });
    }

    if (path.startsWith("/api/")) {
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
          "Allow: /site.webmanifest",
          "Disallow: /",
          "",
          `Sitemap: https://${env.SITE_HOST}/sitemap.xml`,
          ""
        ].join("\n")
      );
    }

    if (path === "/sitemap.xml") {
      return new Response(
        `<?xml version="1.0" encoding="UTF-8"?>\n` +
          `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
          `<url><loc>https://${env.SITE_HOST}/</loc><changefreq>monthly</changefreq></url>` +
          `</urlset>\n`,
        { headers: { "Content-Type": "application/xml; charset=utf-8" } }
      );
    }

    // Falls through to the static assets. Deliberately without the `noindex` header the
    // helpers in http.js add: `/` is the only page meant to be found in a search engine.
    return env.ASSETS.fetch(request);
  },

  /**
   * Housekeeping. Expiry is enforced in every read query, so an expired secret is already
   * unreachable before this runs — the sweep is what keeps the table from growing without
   * bound, not what makes expiry work.
   */
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(
      deleteExpired(env.DB, Date.now()).then((deleted) => {
        if (deleted > 0) console.log(`retention: deleted ${deleted} expired secrets`);
      })
    );
  }
};
