/**
 * Response helpers.
 *
 * `noindex` and `no-store` are on every response this Worker produces, including the
 * error ones. A secret page that a search engine indexes or a shared cache keeps is the
 * failure this whole project exists to avoid, and the safe default belongs here rather
 * than in each handler that has to remember it.
 */

const SECURITY_HEADERS = {
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "Cache-Control": "no-store, max-age=0",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff"
};

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...SECURITY_HEADERS,
      ...extraHeaders
    }
  });
}

export function error(message, status = 400, code = undefined) {
  return json({ error: message, ...(code ? { code } : {}) }, status);
}

export function text(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", ...SECURITY_HEADERS, ...extraHeaders }
  });
}

/** Copies an asset response through, adding the same headers. */
export function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) headers.set(key, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/** Reads a JSON body, or returns null rather than throwing on malformed input. */
export async function readJson(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body : null;
  } catch {
    return null;
  }
}
