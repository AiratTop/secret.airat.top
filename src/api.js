/**
 * The JSON API. Three verbs and one invariant: the server never sees a plaintext secret
 * and never sees the key that would decrypt one.
 *
 *   POST   /api/secrets              store ciphertext, get an id back
 *   GET    /api/secrets/{id}         does it still exist, and what should the UI show
 *   POST   /api/secrets/{id}/reveal  consume a view, return the ciphertext
 *   DELETE /api/secrets/{id}         creator destroys it early (needs the burn token)
 */

import { newId, isSecretId, randomToken } from "./ids.js";
import { insertSecret, getSecretMeta, consumeSecret, burnSecret } from "./db.js";
import { json, error, readJson, MAX_BODY_BYTES } from "./http.js";
import {
  MAX_CIPHERTEXT_BYTES,
  MAX_LABEL_LENGTH,
  MAX_TTL,
  MIN_TTL,
  DEFAULT_TTL,
  MAX_VIEWS_LIMIT,
  DEFAULT_MAX_VIEWS
} from "./limits.js";

const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** Maps a refused body to its response, or returns the parsed body. */
async function body(request) {
  const result = await readJson(request);
  if (result.ok) return { ok: true, value: result.body };

  if (result.reason === "size") {
    return { ok: false, response: error(`Request body must be at most ${MAX_BODY_BYTES} bytes.`, 413) };
  }
  if (result.reason === "type") {
    return { ok: false, response: error("Content-Type must be application/json.", 415) };
  }
  return { ok: false, response: error("Malformed JSON body.", 400) };
}

function isBase64Url(value, maxLength) {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength && BASE64URL.test(value);
}

const LABEL_BLOB = /^[A-Za-z0-9_-]+~[A-Za-z0-9_-]+$/;

function isLabelBlob(value) {
  return typeof value === "string" && value.length <= MAX_LABEL_LENGTH && LABEL_BLOB.test(value);
}

/** Rejects the body with a reason, or returns the normalised secret fields. */
function validateCreate(body) {
  if (!isBase64Url(body.ciphertext, MAX_CIPHERTEXT_BYTES)) {
    return { ok: false, message: `ciphertext must be base64url and at most ${MAX_CIPHERTEXT_BYTES} characters.` };
  }
  // 12 bytes of AES-GCM nonce is 16 base64url characters.
  if (!isBase64Url(body.iv, 32)) {
    return { ok: false, message: "iv must be a base64url-encoded nonce." };
  }
  if (body.kdfSalt !== undefined && body.kdfSalt !== null && !isBase64Url(body.kdfSalt, 64)) {
    return { ok: false, message: "kdfSalt must be base64url when present." };
  }
  /*
   * Required, not optional. The column is nullable for rows written before verifiers
   * existed, and letting a client keep creating rows like that would quietly reintroduce
   * the bug it was added to fix: without one, the server cannot refuse a wrong key and
   * every failed attempt burns a view. SHA-256 in base64url is 43 characters; the value
   * is opaque here and only ever compared.
   */
  if (!isBase64Url(body.verifier, 64)) {
    return { ok: false, message: "verifier is required and must be base64url." };
  }
  // The label is ciphertext too — the server has no idea what it says. Its nonce is
  // carried inline as `iv~ciphertext`, so the label alphabet is base64url plus `~`.
  if (body.label !== undefined && body.label !== null && !isLabelBlob(body.label)) {
    return { ok: false, message: "label must be a base64url nonce and ciphertext joined by '~'." };
  }

  const ttl = body.ttl === undefined ? DEFAULT_TTL : Number(body.ttl);
  if (!Number.isInteger(ttl) || ttl < MIN_TTL || ttl > MAX_TTL) {
    return { ok: false, message: `ttl must be an integer between ${MIN_TTL} and ${MAX_TTL} seconds.` };
  }

  const maxViews = body.maxViews === undefined ? DEFAULT_MAX_VIEWS : Number(body.maxViews);
  if (!Number.isInteger(maxViews) || maxViews < 1 || maxViews > MAX_VIEWS_LIMIT) {
    return { ok: false, message: `maxViews must be an integer between 1 and ${MAX_VIEWS_LIMIT}.` };
  }

  return {
    ok: true,
    value: {
      ciphertext: body.ciphertext,
      iv: body.iv,
      kdfSalt: body.kdfSalt ?? null,
      label: body.label ?? null,
      verifier: body.verifier,
      ttl,
      maxViews
    }
  };
}

async function handleCreate(request, env) {
  const parsed = await body(request);
  if (!parsed.ok) return parsed.response;

  const validated = validateCreate(parsed.value);
  if (!validated.ok) return error(validated.message, 400);

  const now = Date.now();
  const secret = {
    id: newId(now),
    ...validated.value,
    sizeBytes: validated.value.ciphertext.length,
    createdAt: now,
    expiresAt: now + validated.value.ttl * 1000,
    burnToken: randomToken()
  };

  await insertSecret(env.DB, secret);

  // The burn token is returned exactly here and never again: it is the creator's only
  // proof, and a second chance to fetch it would make it readable from the id alone.
  return json(
    {
      id: secret.id,
      url: `https://${env.SITE_HOST}/${secret.id}`,
      burnToken: secret.burnToken,
      expiresAt: secret.expiresAt,
      maxViews: secret.maxViews
    },
    201
  );
}

/**
 * A 404 for a live-but-consumed secret and a 404 for one that never existed are the same
 * response on purpose. Distinguishing them would turn this endpoint into an oracle for
 * whether a given id was ever issued.
 */
async function handleMeta(id, env) {
  const meta = await getSecretMeta(env.DB, id, Date.now());
  if (!meta) return error("This secret does not exist, has expired, or has already been destroyed.", 404, "gone");
  return json(meta);
}

/**
 * The only endpoint with a side effect, and the only one that can refuse without having
 * one. A caller that cannot produce the verifier spends no view: it used to spend one on
 * every attempt, so a single wrong passphrase — or a click with the box still empty —
 * destroyed a burn-after-reading secret.
 *
 * The 403 does tell a caller that this id is live, which the 404s elsewhere are careful
 * not to. No new leak: `GET /api/secrets/{id}` answers that question already, and openly.
 */
async function handleReveal(request, id, env) {
  // A body is optional here: a secret written before verifiers existed is opened without
  // one, and refusing those would make them permanently unreadable.
  let verifier = null;
  if (request.headers.get("Content-Type")) {
    const parsed = await body(request);
    if (!parsed.ok) return parsed.response;
    verifier = typeof parsed.value.verifier === "string" ? parsed.value.verifier : null;
    if (verifier !== null && !isBase64Url(verifier, 64)) {
      return error("verifier must be base64url when present.", 400);
    }
  }

  const result = await consumeSecret(env.DB, id, Date.now(), verifier);
  if (result.ok) return json(result.secret);

  if (result.reason === "verifier") {
    return error("Wrong passphrase, or the link is incomplete. No view was used.", 403, "verifier");
  }
  return error("This secret does not exist, has expired, or has already been destroyed.", 404, "gone");
}

async function handleBurn(request, id, env) {
  const parsed = await body(request);
  if (!parsed.ok) return parsed.response;

  const burnToken = parsed.value.burnToken;
  if (typeof burnToken !== "string" || burnToken.length === 0) {
    return error("A burnToken is required to destroy a secret.", 400);
  }

  const destroyed = await burnSecret(env.DB, id, burnToken);
  if (!destroyed) return error("This secret does not exist or the burn token is wrong.", 404, "gone");
  return json({ destroyed: true });
}

/**
 * Routes anything under `/api/`. Returns null when the path is not ours, so the caller
 * can go on to try the page routes.
 */
export function routeApi(request, env, url) {
  const path = url.pathname;

  if (path === "/api/secrets") {
    if (request.method !== "POST") return error("Method not allowed.", 405);
    return handleCreate(request, env);
  }

  const match = /^\/api\/secrets\/([^/]+)(\/reveal)?$/.exec(path);
  if (!match) return null;

  const [, id, revealSuffix] = match;
  // Checked before touching D1: an id that this platform could not have issued is a
  // scanner, and it should cost a regex rather than a database round trip.
  if (!isSecretId(id)) return error("Not a valid secret id.", 404, "gone");

  if (revealSuffix) {
    if (request.method !== "POST") return error("Method not allowed. Revealing a secret consumes a view.", 405);
    return handleReveal(request, id, env);
  }

  if (request.method === "GET") return handleMeta(id, env);
  if (request.method === "DELETE") return handleBurn(request, id, env);
  return error("Method not allowed.", 405);
}
