/**
 * Browser-side encryption. Nothing in this file has a server counterpart, which is the
 * point: the key is generated here, used here, and put in the URL fragment — the one part
 * of a URL that browsers never send to the origin.
 *
 * Without a passphrase the fragment holds 32 raw bytes that *are* the AES-GCM key. With
 * one, the key is derived with PBKDF2 over the fragment bytes and the passphrase together,
 * so a leaked link alone is not enough and neither is a guessed passphrase.
 */

const PBKDF2_ITERATIONS = 310000;

export function toBase64Url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function importAesKey(bytes) {
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/**
 * Turns the link key — and, when there is one, the passphrase — into an AES-GCM key.
 *
 * The two are concatenated into PBKDF2's password rather than the passphrase being used
 * alone. A passphrase people can remember has nowhere near 256 bits in it, and folding
 * the link key in means the derived key is at least as strong as the no-passphrase case.
 */
export async function deriveKey(linkKeyBytes, passphrase, saltBytes) {
  if (!saltBytes) return importAesKey(linkKeyBytes);

  const passphraseBytes = encoder.encode(passphrase ?? "");
  const material = new Uint8Array(linkKeyBytes.length + passphraseBytes.length);
  material.set(linkKeyBytes, 0);
  material.set(passphraseBytes, linkKeyBytes.length);

  const baseKey = await crypto.subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts a string. Returns everything the API needs plus the link key, which the caller
 * must put in the fragment and must never send anywhere.
 */
export async function encryptText(plaintext, passphrase) {
  const linkKey = randomBytes(32);
  const salt = passphrase ? randomBytes(16) : null;
  const iv = randomBytes(12);
  const key = await deriveKey(linkKey, passphrase, salt);

  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(plaintext));

  return {
    ciphertext: toBase64Url(ciphertext),
    iv: toBase64Url(iv),
    kdfSalt: salt ? toBase64Url(salt) : null,
    linkKey: toBase64Url(linkKey)
  };
}

/**
 * Encrypts the label under the same key, so the "what is this" line shown before opening
 * is no more readable to the server than the secret it describes.
 */
export async function encryptWith(plaintext, linkKeyB64, passphrase, saltB64) {
  const key = await deriveKey(fromBase64Url(linkKeyB64), passphrase, saltB64 ? fromBase64Url(saltB64) : null);
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(plaintext));
  // The label carries its own nonce inline, since the API stores it as one opaque string.
  // `~` separates them: it is not part of the base64url alphabet, so it cannot appear in
  // either half, and it survives a URL untouched.
  return `${toBase64Url(iv)}~${toBase64Url(ciphertext)}`;
}

export async function decryptText(ciphertextB64, ivB64, linkKeyB64, passphrase, saltB64) {
  const key = await deriveKey(fromBase64Url(linkKeyB64), passphrase, saltB64 ? fromBase64Url(saltB64) : null);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(ivB64) },
    key,
    fromBase64Url(ciphertextB64)
  );
  return decoder.decode(plaintext);
}

export async function decryptLabel(labelBlob, linkKeyB64, passphrase, saltB64) {
  const [ivB64, ciphertextB64] = labelBlob.split("~");
  if (!ivB64 || !ciphertextB64) return null;
  return decryptText(ciphertextB64, ivB64, linkKeyB64, passphrase, saltB64);
}
