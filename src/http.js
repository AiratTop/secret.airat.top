/**
 * Response helpers and request-body limits.
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
  "X-Content-Type-Options": "nosniff",
  /*
   * A link carries its decryption key in the fragment, and a fragment survives a
   * redirect that does not carry one of its own (RFC 9110 §7.1.2). So one `http://`
   * paste of a link, on a network with someone in the middle, is enough to send the key
   * to an origin of their choosing. HSTS is what makes the browser refuse to make that
   * first request at all.
   *
   * `includeSubDomains` covers `*.secret.airat.top`, which nothing serves — the point is
   * that nothing ever should over plaintext. Deliberately no `preload`: that is a
   * commitment for the whole of airat.top, made from a hardcoded string in one Worker,
   * and it is not this project's to make.
   */
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains"
};

/*
 * No XSS vector is known today; this is what keeps one from mattering tomorrow, on the
 * page that holds the key and the plaintext at the same moment.
 *
 * `style-src` has to allow inline: Cloudflare Fonts rewrites the Google Fonts link into
 * an inline <style> block after this Worker has produced the response, and a policy
 * without it would leave the site unstyled the moment that feature is on. The Google
 * hosts stay listed for the same reason in reverse — if the zone setting is ever turned
 * off, the pages fall back to loading from them.
 *
 * Everything else is closed: scripts and fetches from this origin only, no frames, no
 * plugins, no <base>, nowhere to submit a form.
 */
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "upgrade-insecure-requests"
].join("; ");

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
  headers.set("Content-Security-Policy", CONTENT_SECURITY_POLICY);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * The landing page, which is the one response allowed to be indexed and cached — so it
 * gets the transport and script protections without the `noindex` and `no-store`.
 */
export function withPageHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("Content-Security-Policy", CONTENT_SECURITY_POLICY);
  headers.set("Strict-Transport-Security", SECURITY_HEADERS["Strict-Transport-Security"]);
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * Nothing this API accepts comes close to this. The cap exists because `request.json()`
 * buffers the whole body first, and a Worker isolate has 128 MB of memory against a
 * platform that will happily deliver a request far larger than anything here is for.
 * Checking the declared length before reading is the cheap half; `readJson` also stops
 * reading a body that lied about its length, or declared none at all.
 */
export const MAX_BODY_BYTES = 128 * 1024;

/** Thrown-free body reader. Returns a reason instead of a body when it will not read one. */
export async function readJson(request) {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return { ok: false, reason: "type" };
  }

  const declared = Number(request.headers.get("Content-Length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    return { ok: false, reason: "size" };
  }

  // A chunked request declares no length, and a dishonest one declares the wrong length,
  // so the bytes are counted as they arrive and the read is abandoned past the cap
  // rather than trusting the header.
  let text;
  try {
    text = await readCapped(request);
  } catch {
    return { ok: false, reason: "size" };
  }

  try {
    const body = JSON.parse(text);
    return body && typeof body === "object" && !Array.isArray(body)
      ? { ok: true, body }
      : { ok: false, reason: "malformed" };
  } catch {
    return { ok: false, reason: "malformed" };
  }
}

async function readCapped(request) {
  if (!request.body) return "";

  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let out = "";

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new RangeError("body too large");
    }
    out += decoder.decode(value, { stream: true });
  }
  return out + decoder.decode();
}
