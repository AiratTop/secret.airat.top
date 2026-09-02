import { describe, it, expect } from "vitest";
import { encryptText, decryptText, deriveVerifier } from "../public_html/crypto.js";

describe("encryption", () => {
  it("round-trips with and without a passphrase, including unicode", async () => {
    for (const passphrase of [null, "correct horse battery staple"]) {
      const secret = "пароль — Ω≈ç√ 🔐\nsecond line";
      const e = await encryptText(secret, passphrase);
      expect(await decryptText(e.ciphertext, e.iv, e.linkKey, passphrase, e.kdfSalt)).toBe(secret);
    }
  });

  it("uses a salt only when there is a passphrase", async () => {
    expect((await encryptText("x", null)).kdfSalt).toBeNull();
    expect((await encryptText("x", "pw")).kdfSalt).not.toBeNull();
  });

  it("refuses the wrong passphrase and the wrong link key", async () => {
    const e = await encryptText("hunter2", "right");
    await expect(decryptText(e.ciphertext, e.iv, e.linkKey, "wrong", e.kdfSalt)).rejects.toThrow();

    const other = await encryptText("other", "right");
    await expect(decryptText(e.ciphertext, e.iv, other.linkKey, "right", e.kdfSalt)).rejects.toThrow();
  });

  it("produces a different key and nonce every time", async () => {
    const runs = await Promise.all(Array.from({ length: 20 }, () => encryptText("same", null)));
    expect(new Set(runs.map((r) => r.linkKey)).size).toBe(20);
    expect(new Set(runs.map((r) => r.iv)).size).toBe(20);
    expect(new Set(runs.map((r) => r.ciphertext)).size).toBe(20);
  });
});

/**
 * The value that lets the server refuse an attempt without spending a view, and without
 * being told the passphrase.
 */
describe("the verifier", () => {
  it("matches the right key and nothing else", async () => {
    const e = await encryptText("hunter2", "right");

    expect(await deriveVerifier(e.linkKey, "right", e.kdfSalt)).toBe(e.verifier);
    expect(await deriveVerifier(e.linkKey, "wrong", e.kdfSalt)).not.toBe(e.verifier);
    expect(await deriveVerifier(e.linkKey, "", e.kdfSalt)).not.toBe(e.verifier);
  });

  /** A truncated link fails the check too, so a broken paste cannot burn a secret. */
  it("catches an incomplete link, passphrase or not", async () => {
    for (const passphrase of [null, "right"]) {
      const e = await encryptText("hunter2", passphrase);
      const truncated = e.linkKey.slice(0, -2) + "AA";
      expect(await deriveVerifier(truncated, passphrase, e.kdfSalt)).not.toBe(e.verifier);
    }
  });

  it("is issued for link-only secrets as well", async () => {
    const e = await encryptText("hunter2", null);
    expect(e.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await deriveVerifier(e.linkKey, null, e.kdfSalt)).toBe(e.verifier);
  });

  /**
   * It is stored on the server and sent over the wire, so it must not be the key. SHA-256
   * over a 256-bit key cannot be inverted, and the point of the assertion is that nobody
   * later "simplifies" this into sending the key itself.
   */
  it("is not the key, nor any prefix of it", async () => {
    const e = await encryptText("hunter2", null);
    expect(e.verifier).not.toBe(e.linkKey);
    expect(e.linkKey.startsWith(e.verifier.slice(0, 8))).toBe(false);
  });
});
