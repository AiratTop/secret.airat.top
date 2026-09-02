-- secret.airat.top — initial schema.
--
-- The server stores ciphertext and nothing else. Encryption happens in the browser
-- (AES-GCM), and the key travels in the URL fragment, which is never sent to the origin.
-- A dump of this table is therefore a pile of opaque blobs: what is stored here cannot
-- be read without a link somebody was given.
--
-- Conventions mirror the other AiratTop projects:
--   ids         TEXT, UUIDv7 rendered as 26-char Crockford base32.
--   timestamps  INTEGER, milliseconds since epoch (UTC) — cheap to compare in a WHERE.
--   booleans    INTEGER 0/1 — SQLite has no boolean type.

CREATE TABLE secrets (
  id            TEXT PRIMARY KEY,

  -- base64url of the AES-GCM output, and its 12-byte nonce. Kept apart so the nonce can
  -- be handed to `crypto.subtle.decrypt` without slicing a blob on the client.
  ciphertext    TEXT NOT NULL,
  iv            TEXT NOT NULL,

  -- Set when the creator added a passphrase on top of the link key: the client then
  -- derives the key with PBKDF2 over this salt instead of reading it from the fragment.
  -- The passphrase itself never reaches the server, so this flag is all the UI has to go
  -- on when it decides whether to prompt.
  kdf_salt      TEXT,

  -- Free-form label shown before the secret is revealed ("staging DB password").
  -- Encrypted client-side like everything else; NULL when the creator left it empty.
  label         TEXT,

  -- Burn-after-reading is `max_views = 1`. Anything higher is a link that survives a
  -- few opens, which is what makes it usable over a channel that prefetches URLs.
  max_views     INTEGER NOT NULL DEFAULT 1 CHECK (max_views > 0),
  views         INTEGER NOT NULL DEFAULT 0 CHECK (views >= 0),

  -- Ciphertext length in bytes, for the size cap and for stats. Not the plaintext size.
  size_bytes    INTEGER NOT NULL,

  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,

  -- Lets the creator destroy a secret early from the "link created" screen. Random,
  -- returned once at creation, never derivable from the id.
  burn_token    TEXT NOT NULL
);

-- The cron sweep's only query.
CREATE INDEX ix_secrets_expires ON secrets (expires_at);
