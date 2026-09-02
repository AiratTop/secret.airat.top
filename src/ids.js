/**
 * Identifiers: UUIDv7 rendered as 26 characters of Crockford base32.
 *
 * Same shape as the ids in orator-space, and for the same reasons — sortable by creation
 * time, case-insensitive alphabet with no look-alike characters, and short enough to sit
 * in a URL somebody pastes into a chat window:
 *
 *   https://secret.airat.top/06G670V9KDR018E1HQDG34K3X4
 *
 * 128 bits of which 74 are random. Guessing a live id is not a threat model this has to
 * defend against on its own — the decryption key is in the fragment and never reaches the
 * server — but an unguessable id is what keeps a scanner from finding a secret to burn.
 */

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ID_LENGTH = 26;

/** Encodes 16 bytes as 26 Crockford base32 characters (130 bits, top 2 bits always zero). */
export function encodeId(bytes) {
  if (bytes.length !== 16) throw new RangeError(`expected 16 bytes, got ${bytes.length}`);
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  value <<= 2n; // pad 128 -> 130 bits so the string is exactly 26 chars
  const out = new Array(ID_LENGTH);
  for (let i = ID_LENGTH - 1; i >= 0; i--) {
    out[i] = CROCKFORD[Number(value & 31n)];
    value >>= 5n;
  }
  return out.join("");
}

export function decodeId(id) {
  if (id.length !== ID_LENGTH) throw new RangeError(`expected ${ID_LENGTH} characters, got ${id.length}`);
  let value = 0n;
  for (const char of id) {
    const index = CROCKFORD.indexOf(char);
    if (index < 0) throw new RangeError(`invalid Crockford base32 character: ${char}`);
    value = (value << 5n) | BigInt(index);
  }
  value >>= 2n;
  const bytes = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) {
    bytes[i] = Number(value & 255n);
    value >>= 8n;
  }
  return bytes;
}

const ID_PATTERN = new RegExp(`^[${CROCKFORD}]{${ID_LENGTH}}$`);

/**
 * Could this platform have issued this id?
 *
 * The alphabet and length are the cheap half. The encoding also has to be canonical:
 * `encodeId` pads 128 bits out to 130, so the low two bits of the last character are
 * always zero, and a string that sets them decodes to the *same sixteen bytes*. Without
 * the round trip, one row would have four spellings and `/{id}` would answer to all of
 * them — which is a cache key problem and a canonical-URL problem at once.
 */
export function isSecretId(value) {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) return false;
  return encodeId(decodeId(value)) === value;
}

/** A fresh UUIDv7, already encoded. */
export function newId(now = Date.now()) {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  const ms = BigInt(now);
  for (let i = 0; i < 6; i++) bytes[i] = Number((ms >> BigInt(40 - i * 8)) & 0xffn);
  bytes[6] = (bytes[6] & 0x0f) | 0x70; // version 7
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10

  return encodeId(bytes);
}

/** Milliseconds since epoch, read back out of the leading 48 bits. */
export function idTimestamp(id) {
  const bytes = decodeId(id);
  let ms = 0;
  for (let i = 0; i < 6; i++) ms = ms * 256 + bytes[i];
  return ms;
}

/** 32 bytes of base64url randomness — used for the burn token. */
export function randomToken(byteLength = 24) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
