import { describe, it, expect } from "vitest";
import { call, post, fromAddress, uniqueAddress } from "./helpers.js";
import { MAX_BODY_BYTES } from "../src/http.js";

const validBody = {
  ciphertext: "Y2lwaGVy",
  iv: "AAAAAAAAAAAAAAAA",
  verifier: "the-right-one",
  ttl: 3600,
  maxViews: 1
};

/**
 * The one endpoint that can take the service down without any cleverness: an
 * unauthenticated write, up to 64 KB, kept for up to thirty days, in front of a single D1
 * that serialises its queries and has a hard size ceiling.
 */
describe("flood protection", () => {
  it("cuts off a caller creating secrets in bulk", async () => {
    const address = uniqueAddress();
    const statuses: number[] = [];

    for (let i = 0; i < 14; i++) {
      const response = await fromAddress(address, "/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(validBody)
      });
      statuses.push(response.status);
    }

    expect(statuses.filter((s) => s === 201).length).toBeLessThanOrEqual(10);
    expect(statuses).toContain(429);
  });

  it("meters each caller separately", async () => {
    const busy = uniqueAddress();
    for (let i = 0; i < 12; i++) {
      await fromAddress(busy, "/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(validBody)
      });
    }
    expect(
      (
        await fromAddress(busy, "/api/secrets", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(validBody)
        })
      ).status
    ).toBe(429);

    // Someone else is unaffected — a shared counter would make one flooder a global outage.
    const bystander = await fromAddress(uniqueAddress(), "/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validBody)
    });
    expect(bystander.status).toBe(201);
  });

  /**
   * Reading is metered under its own namespace. Sharing one with writes would let a burst
   * of reads spend a writer's allowance, and worse, would let a flood of creates lock a
   * recipient out of a secret that is about to expire.
   */
  it("does not let writes exhaust a reader's allowance", async () => {
    const address = uniqueAddress();
    const created = await fromAddress(address, "/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validBody)
    });
    const { id } = (await created.json()) as { id: string };

    for (let i = 0; i < 12; i++) {
      await fromAddress(address, "/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(validBody)
      });
    }

    expect((await fromAddress(address, `/api/secrets/${id}`)).status).toBe(200);
  });

  it("says when to come back", async () => {
    const address = uniqueAddress();
    let response = await fromAddress(address, "/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validBody)
    });
    for (let i = 0; i < 14 && response.status !== 429; i++) {
      response = await fromAddress(address, "/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(validBody)
      });
    }

    expect(response.status).toBe(429);
    expect(response.headers.get("Retry-After")).toBe("60");
    expect(((await response.json()) as { code: string }).code).toBe("rate_limited");
  });
});

/**
 * `request.json()` buffers the whole body before any field can be looked at, and a Worker
 * isolate has 128 MB against a platform that will deliver far more than that. The
 * ciphertext cap protects one field; this protects the request.
 */
describe("request bodies", () => {
  it("refuses a body past the cap with 413, without parsing it", async () => {
    const response = await call("/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...validBody, padding: "A".repeat(MAX_BODY_BYTES) })
    });
    expect(response.status).toBe(413);
  });

  /** A chunked request declares no length, so the cap cannot rely on the header alone. */
  it("refuses an oversized body that declares no length", async () => {
    const oversized = new Blob(["A".repeat(MAX_BODY_BYTES + 1024)]).stream();
    const response = await call("/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: oversized
    });
    expect(response.status).toBe(413);
  });

  it("requires the content type it parses", async () => {
    const response = await call("/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify(validBody)
    });
    expect(response.status).toBe(415);
  });

  it("still accepts a body comfortably inside the cap", async () => {
    expect((await post("/api/secrets", validBody)).status).toBe(201);
  });
});

describe("the verifier is required for new secrets", () => {
  it("refuses a create without one", async () => {
    const { verifier, ...withoutVerifier } = validBody;
    const response = await post("/api/secrets", withoutVerifier);
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toMatch(/verifier is required/);
  });

  it("refuses one that is not base64url", async () => {
    expect((await post("/api/secrets", { ...validBody, verifier: "not base64!" })).status).toBe(400);
  });
});
