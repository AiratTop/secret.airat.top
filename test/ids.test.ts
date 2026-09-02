import { describe, it, expect } from "vitest";
import { encodeId, decodeId, isSecretId, newId, idTimestamp, randomToken } from "../src/ids.js";

describe("identifiers", () => {
  it("round-trips 16 bytes through 26 characters", () => {
    const bytes = new Uint8Array(16).fill(0xab);
    const id = encodeId(bytes);
    expect(id).toHaveLength(26);
    expect(decodeId(id)).toEqual(bytes);
  });

  it("mints sortable UUIDv7s that carry their own timestamp", () => {
    const before = Date.now();
    const id = newId();
    expect(isSecretId(id)).toBe(true);
    expect(idTimestamp(id)).toBeGreaterThanOrEqual(before);

    const bytes = decodeId(id);
    expect(bytes[6]! >> 4).toBe(0x7);
    expect(bytes[8]! >> 6).toBe(0b10);
  });

  it("orders by creation time as strings", () => {
    const early = newId(1_600_000_000_000);
    const late = newId(1_700_000_000_000);
    expect(early < late).toBe(true);
  });

  /**
   * The reason `isSecretId` decodes and re-encodes rather than only matching a pattern.
   * `encodeId` pads 128 bits out to 130, so the low two bits of the last character are
   * always zero. A string that sets them passes the regex and decodes to the *same
   * sixteen bytes* — a second spelling of one secret, and a second URL for it.
   */
  it("rejects a non-canonical spelling of a real id", () => {
    const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    const id = newId();

    // The padding puts the last byte's low three bits in the top of the final character,
    // so its index is always a multiple of four — the two spare bits are the slack an
    // alias exploits.
    const lastIndex = CROCKFORD.indexOf(id[25]!);
    expect(lastIndex % 4).toBe(0);

    for (const slack of [1, 2, 3]) {
      const alias = id.slice(0, 25) + CROCKFORD[lastIndex + slack];
      expect(alias).not.toBe(id);
      expect(decodeId(alias)).toEqual(decodeId(id)); // same sixteen bytes...
      expect(isSecretId(alias)).toBe(false); // ...and still not a valid id
    }
  });

  it("rejects wrong lengths and characters outside the alphabet", () => {
    expect(isSecretId("")).toBe(false);
    expect(isSecretId(newId().slice(0, 25))).toBe(false);
    expect(isSecretId(newId() + "0")).toBe(false);
    // U, I, L and O are absent from Crockford base32 precisely because they are confusable.
    expect(isSecretId("06G670V9KDR018E1HQDG34K3XU")).toBe(false);
    expect(isSecretId("06g670v9kdr018e1hqdg34k3x4")).toBe(false);
    expect(isSecretId(null)).toBe(false);
    expect(isSecretId(12345)).toBe(false);
  });

  it("refuses to encode anything but 16 bytes", () => {
    expect(() => encodeId(new Uint8Array(15))).toThrow(RangeError);
  });

  it("mints burn tokens that are url-safe and unique", () => {
    const tokens = new Set(Array.from({ length: 200 }, () => randomToken()));
    expect(tokens.size).toBe(200);
    for (const token of tokens) expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});
