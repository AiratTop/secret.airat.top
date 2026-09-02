/**
 * The numbers, in one place, because the client validates against the same set and the
 * two drifting apart is how a form starts accepting what the API rejects.
 */

/** Ciphertext cap. AES-GCM adds 16 bytes of tag and base64 adds a third, so this is
 *  roughly 48 KB of plaintext — comfortably more than a credential, far short of a file. */
export const MAX_CIPHERTEXT_BYTES = 64 * 1024;

export const MAX_LABEL_LENGTH = 2048;

/** Selectable lifetimes, in seconds. The first is the default. */
export const TTL_OPTIONS = [
  { value: 86400, label: "24 hours" },
  { value: 3600, label: "1 hour" },
  { value: 300, label: "5 minutes" },
  { value: 604800, label: "7 days" },
  { value: 2592000, label: "30 days" }
];

export const DEFAULT_TTL = 86400;
export const MAX_TTL = 2592000;
export const MIN_TTL = 60;

/** How many times a link may be opened. One is burn-after-reading. */
export const MAX_VIEWS_LIMIT = 10;
export const DEFAULT_MAX_VIEWS = 1;
