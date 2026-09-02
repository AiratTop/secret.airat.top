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

  it("allows a crawler the assets it needs to render the page", async () => {
    const robots = await (await call("/robots.txt")).text();
    const html = await (await call("/")).text();
    const assets = [...html.matchAll(/(?:src|href)="(\/[^"]+\.(?:js|css))"/g)].map((m) => m[1]);

    expect(assets.length).toBeGreaterThan(0);
    for (const asset of assets) expect(robots, `${asset} is blocked`).toContain(`Allow: ${asset}`);
  });

  it("loads no third-party script", async () => {
    const html = await (await call("/")).text();
    const scripts = [...html.matchAll(/<script[^>]*src="([^"]*)"/g)].map((m) => m[1]);
    for (const src of scripts) expect(src.startsWith("/")).toBe(true);
    expect(html).not.toContain("googletagmanager.com");
  });
});

/**
 * The pages and their scripts are joined only by string ids, and nothing else checks that
 * the join holds — rename an element and the page keeps serving, keeps passing every other
 * test, and throws on the first click instead.
 */
describe("the scripts and the markup agree", () => {
  const pages: [string, string][] = [
    ["/index.html", "/app.js"],
    ["/view.html", "/view.js"]
  ];

  it.each(pages)("every id %s's script reads exists in it", async (page, script) => {
    const markup = await (await call(page)).text();
    const code = await (await call(script)).text();

    const wanted = [...code.matchAll(/getElementById\("([^"]+)"\)/g)].map((m) => m[1]!);
    const present = new Set([...markup.matchAll(/id="([^"]+)"/g)].map((m) => m[1]!));

    expect(wanted.length).toBeGreaterThan(0);
    for (const id of wanted) expect(present, `${script} reads #${id}`).toContain(id);
  });

  it.each(pages)("%s imports only modules this origin serves", async (page) => {
    const markup = await (await call(page)).text();
    const modules = [...markup.matchAll(/<script[^>]*src="([^"]+)"/g)].map((m) => m[1]!);
    for (const src of modules) {
      expect(src.startsWith("/")).toBe(true);
      expect((await call(src)).status, `${src} is referenced but not served`).toBe(200);
    }
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
