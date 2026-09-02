# Security Policy

## Reporting a Vulnerability

Please do not open a public issue for a security problem.

Email [mail@airat.top](mailto:mail@airat.top) with the details — what you found, how to
reproduce it, and what you think the impact is. You will get an acknowledgement, and you
are welcome to be credited in the fix unless you would rather not be.

## What This Service Guarantees

A secret is encrypted in the browser with AES-256-GCM. The key is generated there and
placed in the URL fragment, which browsers never transmit to the origin, so the Worker,
its D1 database, its logs and its backups hold only ciphertext. Whoever holds a copy of
the database cannot read what is in it.

An optional passphrase is folded into the key with PBKDF2 (310 000 iterations, SHA-256)
over a per-secret salt, so a leaked link is not sufficient on its own.

A secret is destroyed when its view allowance runs out or its deadline passes, whichever
comes first. Expiry is enforced in every read query, so an expired secret is unreadable
before any cleanup has run.

## What It Does Not Guarantee

These are properties of the design rather than bugs. Reports of them are still welcome if
you think one is worse than stated, but they are known:

- **The link is the secret.** Anyone who obtains it before the recipient can read the
  secret and destroy it in the process. Whatever channel carries the link is as trusted as
  the secret it carries.
- **The server serves the code that decrypts.** A visitor trusts this origin to send
  honest JavaScript. Client-side encryption protects against a compromised database, a
  subpoena, or a careless backup. It does not protect against a compromised origin.
- **The browser is not hardened.** The fragment lands in history and may reach an
  extension, a clipboard manager, or a synced tab. The plaintext lives in the DOM after
  it is revealed.
- **Deletion is logical.** A row is deleted from D1 when a secret burns. Recovery of
  overwritten pages from the underlying storage is out of scope, and the ciphertext would
  be useless without the key in any case.
- **Metadata is visible to the server.** Ciphertext length, creation time, expiry, view
  allowance, and whether a passphrase is set are stored in the clear. The identifier
  encodes its own creation time.
- **No rate limiting today.** Identifiers are 74 bits of randomness and guessing one is
  not practical, but there is no throttle on attempts.

## Supported Versions

The deployed version at https://secret.airat.top is the only supported one. Fixes land on
`main` and deploy from there.
