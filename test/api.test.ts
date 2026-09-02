import { describe, it, expect, beforeEach } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { BASE, call, readJson, post } from "./helpers.js";
import { newId, randomToken } from "../src/ids.js";


/**
 * A create request. The verifier is required now, so the default carries one — a fixed
 * string rather than a real hash, because the server only ever compares it and a test
 * that derives one would be testing the browser's crypto instead of the API's contract.
 */
function createBody(overrides: Record<string, unknown> = {}) {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ciphertext: "Y2lwaGVy",
      iv: "AAAAAAAAAAAAAAAA",
      verifier: "the-right-one",
      ttl: 3600,
      maxViews: 1,
      ...overrides
    })
  };
}

async function createSecret(overrides: Record<string, unknown> = {}) {
  const response = await call("/api/secrets", createBody(overrides));
  expect(response.status).toBe(201);
  return response.json() as Promise<{ id: string; url: string; burnToken: string; expiresAt: number; maxViews: number }>;
}

/** Writes a row straight to D1, for the states the API will not produce — an expired one. */
async function insertRaw(fields: Record<string, unknown>) {
  const row = {
    id: newId(),
    ciphertext: "Y2lwaGVy",
    iv: "AAAAAAAAAAAAAAAA",
    kdf_salt: null,
    label: null,
    max_views: 1,
    views: 0,
    size_bytes: 8,
    created_at: Date.now(),
    expires_at: Date.now() + 60_000,
    burn_token: randomToken(),
    verifier: null,
    ...fields
  };
  await env.DB.prepare(
    `INSERT INTO secrets (id, ciphertext, iv, kdf_salt, label, max_views, views, size_bytes, created_at, expires_at, burn_token, verifier)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      row.id, row.ciphertext, row.iv, row.kdf_salt, row.label, row.max_views,
      row.views, row.size_bytes, row.created_at, row.expires_at, row.burn_token, row.verifier
    )
    .run();
  return row;
}

beforeEach(async () => {
  await env.DB.prepare("DELETE FROM secrets").run();
});

describe("creating a secret", () => {
  it("stores ciphertext and hands back a link and a burn token", async () => {
    const created = await createSecret();
    expect(created.id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(created.url).toBe(`${BASE}/${created.id}`);
    expect(created.burnToken).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(created.expiresAt).toBeGreaterThan(Date.now());
  });

  it("never returns the burn token again", async () => {
    const created = await createSecret();
    const meta = await readJson(await call(`/api/secrets/${created.id}`));
    expect(meta).not.toHaveProperty("burnToken");

    const revealed = await readJson(await post(`/api/secrets/${created.id}/reveal`, { verifier: "the-right-one" }));
    expect(revealed).not.toHaveProperty("burnToken");
  });

  it("rejects input the client should never have sent", async () => {
    const cases: [string, Record<string, unknown>][] = [
      ["ciphertext over the size cap", { ciphertext: "A".repeat(65 * 1024) }],
      ["ciphertext that is not base64url", { ciphertext: "not base64!" }],
      ["empty ciphertext", { ciphertext: "" }],
      ["a missing nonce", { iv: undefined }],
      ["a ttl below the floor", { ttl: 30 }],
      ["a ttl beyond 30 days", { ttl: 2_592_001 }],
      ["a fractional ttl", { ttl: 60.5 }],
      ["zero views", { maxViews: 0 }],
      ["more views than allowed", { maxViews: 11 }],
      ["a label that is not a nonce and ciphertext", { label: "plaintext" }],
      ["a kdf salt that is not base64url", { kdfSalt: "!!" }]
    ];

    for (const [name, overrides] of cases) {
      const response = await call("/api/secrets", createBody(overrides));
      expect(response.status, name).toBe(400);
    }
  });

  it("rejects a malformed body rather than throwing", async () => {
    const response = await call("/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not json"
    });
    expect(response.status).toBe(400);
  });

  it("only answers POST", async () => {
    expect((await call("/api/secrets")).status).toBe(405);
  });
});

describe("reading metadata", () => {
  /**
   * The whole reason revealing is a POST. A link previewer, a mail scanner or a chat
   * client unfurling the URL will GET this; if that consumed a view the secret would be
   * gone before its recipient ever clicked.
   */
  it("does not consume a view, however many times it is asked", async () => {
    const created = await createSecret({ maxViews: 1 });

    for (let i = 0; i < 5; i++) {
      const meta = await readJson(await call(`/api/secrets/${created.id}`));
      expect(meta.viewsLeft).toBe(1);
    }

    const revealed = await post(`/api/secrets/${created.id}/reveal`, { verifier: "the-right-one" });
    expect(revealed.status).toBe(200);
  });

  it("says whether a passphrase is needed, and hands over the salt to derive with", async () => {
    const created = await createSecret({ kdfSalt: "c2FsdHNhbHRzYWx0c2E" });
    const meta = await readJson(await call(`/api/secrets/${created.id}`));
    expect(meta.hasPassword).toBe(true);
    expect(meta.kdfSalt).toBe("c2FsdHNhbHRzYWx0c2E");
  });

  it("never returns the ciphertext", async () => {
    const created = await createSecret();
    const meta = await readJson(await call(`/api/secrets/${created.id}`));
    expect(meta).not.toHaveProperty("ciphertext");
  });
});

describe("revealing", () => {
  it("returns the ciphertext and destroys a one-view secret", async () => {
    const created = await createSecret({ maxViews: 1 });
    const revealed = await readJson(await post(`/api/secrets/${created.id}/reveal`, { verifier: "the-right-one" }));

    expect(revealed.ciphertext).toBe("Y2lwaGVy");
    expect(revealed.burned).toBe(true);
    expect(revealed.viewsLeft).toBe(0);

    const row = await env.DB.prepare("SELECT id FROM secrets WHERE id = ?").bind(created.id).first();
    expect(row, "the row itself should be gone, not merely unreadable").toBeNull();
  });

  it("counts down a multi-view secret and destroys it on the last one", async () => {
    const created = await createSecret({ maxViews: 3 });

    for (const expected of [2, 1, 0]) {
      const revealed = await readJson(await post(`/api/secrets/${created.id}/reveal`, { verifier: "the-right-one" }));
      expect(revealed.viewsLeft).toBe(expected);
      expect(revealed.burned).toBe(expected === 0);
    }

    expect((await post(`/api/secrets/${created.id}/reveal`, { verifier: "the-right-one" })).status).toBe(404);
  });

  /**
   * The reason `consumeSecret` increments inside the statement that reads the row. Split
   * into a read and a write, both of these would win and one secret would be handed to
   * two readers.
   */
  it("burns exactly once when two readers arrive together", async () => {
    const created = await createSecret({ maxViews: 1 });

    const responses = await Promise.all(
      Array.from({ length: 8 }, () => post(`/api/secrets/${created.id}/reveal`, { verifier: "the-right-one" }))
    );

    const winners = responses.filter((r) => r.status === 200);
    expect(winners).toHaveLength(1);
    expect(responses.filter((r) => r.status === 404)).toHaveLength(7);
  });

  it("hands out a 2-view secret to exactly two of five simultaneous readers", async () => {
    const created = await createSecret({ maxViews: 2 });
    const responses = await Promise.all(
      Array.from({ length: 5 }, () => post(`/api/secrets/${created.id}/reveal`, { verifier: "the-right-one" }))
    );
    expect(responses.filter((r) => r.status === 200)).toHaveLength(2);
  });

  /**
   * The reported bug, in the order it was hit: a one-view secret with a passphrase, the
   * reveal button pressed with the box still empty, and then the passphrase typed — by
   * which point the only view was gone.
   */
  it("does not spend a view on an attempt that cannot decrypt", async () => {
    const created = await createSecret({ kdfSalt: "c2FsdA", maxViews: 1 });

    // No verifier at all — the empty-passphrase click, as reported.
    const noVerifier = await call(`/api/secrets/${created.id}/reveal`, { method: "POST" });
    expect(noVerifier.status).toBe(403);

    const wrongVerifier = await call(`/api/secrets/${created.id}/reveal`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verifier: "the-wrong-one" })
    });
    expect(wrongVerifier.status).toBe(403);

    // Untouched: still there, still one view, and it still opens.
    const meta = await readJson(await call(`/api/secrets/${created.id}`));
    expect(meta.viewsLeft).toBe(1);

    const right = await call(`/api/secrets/${created.id}/reveal`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verifier: "the-right-one" })
    });
    expect(right.status).toBe(200);
    expect((await readJson(right)).burned).toBe(true);
  });

  it("survives a run of wrong attempts and still opens once", async () => {
    const created = await createSecret({ kdfSalt: "c2FsdA", verifier: "right", maxViews: 1 });

    for (let i = 0; i < 20; i++) {
      const response = await call(`/api/secrets/${created.id}/reveal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verifier: `guess-${i}` })
      });
      expect(response.status).toBe(403);
    }

    const row = await env.DB.prepare("SELECT views FROM secrets WHERE id = ?").bind(created.id).first();
    expect(row!.views).toBe(0);
  });

  it("refuses a wrong key without saying whether it was the passphrase or the link", async () => {
    const created = await createSecret({ verifier: "right" });
    const response = await call(`/api/secrets/${created.id}/reveal`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verifier: "wrong" })
    });
    expect(response.status).toBe(403);
    expect((await readJson(response)).code).toBe("verifier");
  });

  /**
   * A secret stored before verifiers existed carries none. It must keep opening rather
   * than becoming permanently unreadable, which is what a mandatory check would do.
   */
  it("still opens a secret that predates verifiers", async () => {
    const row = await insertRaw({ verifier: null });
    const response = await call(`/api/secrets/${row.id}/reveal`, { method: "POST" });
    expect(response.status).toBe(200);
  });

  it("does not let a wrong verifier destroy an expired-looking secret either", async () => {
    const row = await insertRaw({ expires_at: Date.now() - 1, verifier: "right" });
    const response = await call(`/api/secrets/${row.id}/reveal`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verifier: "wrong" })
    });
    // Gone beats wrong-key: an expired secret must not be distinguishable by guessing.
    expect(response.status).toBe(404);
  });

  it("only answers POST, because it has a side effect", async () => {
    const created = await createSecret();
    expect((await call(`/api/secrets/${created.id}/reveal`)).status).toBe(405);
  });
});

describe("expiry", () => {
  it("refuses an expired secret before any sweep has run", async () => {
    const row = await insertRaw({ expires_at: Date.now() - 1 });

    expect((await call(`/api/secrets/${row.id}`)).status).toBe(404);
    expect((await call(`/api/secrets/${row.id}/reveal`, { method: "POST" })).status).toBe(404);

    // Still on disk — invisible is not the same as deleted, and that is the point.
    const still = await env.DB.prepare("SELECT id FROM secrets WHERE id = ?").bind(row.id).first();
    expect(still).not.toBeNull();
  });

  it("sweeps expired rows on the cron and leaves live ones alone", async () => {
    const expired = await insertRaw({ expires_at: Date.now() - 1 });
    const live = await insertRaw({ expires_at: Date.now() + 600_000 });

    const ctx = createExecutionContext();
    await worker.scheduled({ cron: "*/15 * * * *", scheduledTime: Date.now(), noRetry() {} } as any, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(await env.DB.prepare("SELECT id FROM secrets WHERE id = ?").bind(expired.id).first()).toBeNull();
    expect(await env.DB.prepare("SELECT id FROM secrets WHERE id = ?").bind(live.id).first()).not.toBeNull();
  });
});

describe("destroying early", () => {
  it("needs the burn token", async () => {
    const created = await createSecret({ maxViews: 5 });

    const wrong = await call(`/api/secrets/${created.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ burnToken: "not-the-token" })
    });
    expect(wrong.status).toBe(404);
    expect((await call(`/api/secrets/${created.id}`)).status, "a failed burn must not destroy it").toBe(200);

    const right = await call(`/api/secrets/${created.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ burnToken: created.burnToken })
    });
    expect(right.status).toBe(200);
    expect((await call(`/api/secrets/${created.id}`)).status).toBe(404);
  });

  it("rejects a request with no token at all", async () => {
    const created = await createSecret();
    const response = await call(`/api/secrets/${created.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    expect(response.status).toBe(400);
  });
});

/**
 * Telling "never existed" from "already read" would let anyone walk the id space and learn
 * which secrets were ever issued, and roughly when. One response, one message.
 */
describe("not leaking which ids exist", () => {
  it("answers identically for a consumed secret, an expired one and one never issued", async () => {
    const consumed = await createSecret();
    await post(`/api/secrets/${consumed.id}/reveal`, { verifier: "the-right-one" });
    const expired = await insertRaw({ expires_at: Date.now() - 1 });
    const neverIssued = newId();

    const bodies = await Promise.all(
      [consumed.id, expired.id, neverIssued].map(async (id) => {
        const response = await call(`/api/secrets/${id}`);
        expect(response.status).toBe(404);
        return response.text();
      })
    );

    expect(new Set(bodies).size).toBe(1);
  });
});
