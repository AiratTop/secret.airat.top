import { describe, it, expect } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { newId } from "../src/ids.js";

const BASE = "https://secret.airat.top";

async function call(path: string, init?: RequestInit) {
  const ctx = createExecutionContext();
  const response = await worker.fetch(new Request(`${BASE}${path}`, init), env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

describe("the secret page", () => {
  /**
   * The same shell for a live id and a long-dead one. If the server rendered anything
   * about the secret, a previewer that never runs the script would learn something — and
   * the difference between two responses is itself a signal.
   */
  it("serves one static shell for any well-formed id, live or not", async () => {
    const live = await (await call("/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext: "Y2lwaGVy", iv: "AAAAAAAAAAAAAAAA", ttl: 3600, maxViews: 1 })
    })).json();

    const forLive = await call(`/${live.id}`);
    const forUnknown = await call(`/${newId()}`);

    expect(forLive.status).toBe(200);
    expect(forUnknown.status).toBe(200);
    expect(await forLive.text()).toBe(await forUnknown.text());
  });

  it("keeps a secret out of search results and out of caches", async () => {
    const response = await call(`/${newId()}`);
    expect(response.headers.get("x-robots-tag")).toContain("noindex");
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("redirects a lowercase id to the one canonical URL", async () => {
    const id = newId();
    const response = await call(`/${id.toLowerCase()}`);
    expect(response.status).toBe(301);
    expect(response.headers.get("location")).toBe(`${BASE}/${id}`);
  });

  it("does not treat a non-id path as a secret", async () => {
    expect((await call("/about")).status).toBe(404);
    expect((await call("/06G670V9KDR018E1HQDG34K3X")).status).toBe(404); // one char short
  });
});

describe("the landing page", () => {
  /** The one page meant to be found. Every other response carries noindex. */
  it("is indexable", async () => {
    const response = await call("/");
    expect(response.status).toBe(200);
    expect(response.headers.get("x-robots-tag")).toBeNull();
  });

  it("loads no third-party script", async () => {
    const html = await (await call("/")).text();
    const scripts = [...html.matchAll(/<script[^>]*src="([^"]*)"/g)].map((m) => m[1]);
    for (const src of scripts) expect(src.startsWith("/")).toBe(true);
    expect(html).not.toContain("googletagmanager.com");
  });
});

describe("crawler directives", () => {
  it("allows the landing page and disallows everything else", async () => {
    const robots = await (await call("/robots.txt")).text();
    expect(robots).toContain("Allow: /$");
    expect(robots).toContain("Disallow: /");
    // Google fetches a favicon with a crawler; blocking it costs the landing page its icon.
    expect(robots).toContain("Allow: /favicon.ico");
    expect(robots).toContain(`Sitemap: ${BASE}/sitemap.xml`);
  });

  it("lists only the landing page in the sitemap", async () => {
    const sitemap = await (await call("/sitemap.xml")).text();
    expect(sitemap).toContain(`<loc>${BASE}/</loc>`);
    expect([...sitemap.matchAll(/<loc>/g)]).toHaveLength(1);
  });
});

describe("health", () => {
  it("reports ok when the schema is there", async () => {
    const response = await call("/health");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ok", database: "ok" });
  });
});

describe("unknown endpoints", () => {
  it("404s under /api/ rather than falling through to an asset", async () => {
    expect((await call("/api/nope")).status).toBe(404);
  });
});
