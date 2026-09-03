# secret.airat.top

[![secret.airat.top](https://raw.githubusercontent.com/AiratTop/secret.airat.top/main/public_html/screenshot.png)](https://secret.airat.top/)

Share secrets with self-destructing links.

A password, a token, or a note is encrypted in your browser, stored as ciphertext, and
handed over as a link that destroys itself — after one read by default, or when its timer
runs out.

- Live site: https://secret.airat.top
- Status page: https://status.airat.top

## How it works

1. The browser generates a 256-bit AES-GCM key and encrypts the secret with it.
2. Only the ciphertext is sent to the Worker, which stores it in Cloudflare D1.
3. The key is appended to the link as a URL fragment — `https://secret.airat.top/{id}#{key}`.
   Browsers never send a fragment to the server, so the key stays out of request logs,
   the database, and backups.
4. The recipient opens the link and clicks to reveal. That request consumes a view; when
   the last view is used the row is deleted.

A dump of the database is a pile of blobs nobody can read. Losing the link loses the
secret, which is the trade this design makes on purpose.

There are no analytics and no third-party scripts on any page. A counter would report
`location.href`, and on a secret's page that string contains the decryption key.

An optional passphrase is folded into the key with PBKDF2 (310 000 iterations, SHA-256),
so a link that leaks is not enough on its own.

Because the server cannot tell a right passphrase from a wrong one, the client sends a
*verifier* — a hash of the derived key — which the server compares before spending a view.
A wrong passphrase or an incomplete link is therefore refused for free, rather than
destroying a burn-after-reading secret on the first mistyped attempt.

## API

Base URL: `https://secret.airat.top`. No key and no account. Every response is JSON,
`no-store`, and `noindex`.

Rate limited per caller: 10 creates a minute, and 60 a minute for everything else —
revealing included, so a busy creator cannot lock a recipient out of opening a link.
Refusals are `429` with a `Retry-After` giving the real remainder of the window. Request
bodies are capped at 128 KB and must be `application/json`.

One thing to understand before reading further: **the API cannot create a usable link on
its own.** The server never receives a key, so a client must encrypt the secret itself and
append the key to the URL as a fragment. `POST /api/secrets` stores an opaque blob and has
no idea whether it is AES-GCM or noise. The reference implementation is
[`public_html/crypto.js`](public_html/crypto.js), which is 100 lines and has no
dependencies.

| Method | Path | Effect |
| --- | --- | --- |
| `POST` | `/api/secrets` | Store ciphertext, get an id, URL and burn token |
| `GET` | `/api/secrets/{id}` | Metadata only — does not consume a view |
| `POST` | `/api/secrets/{id}/reveal` | Consume a view and return the ciphertext |
| `DELETE` | `/api/secrets/{id}` | Destroy early; needs the burn token |
| `GET` | `/api/config` | Limits the UI validates against |
| `GET` | `/health` | Liveness, including a D1 round trip |

### `POST /api/secrets`

| Field | Required | Notes |
| --- | --- | --- |
| `ciphertext` | yes | base64url, at most 65536 characters |
| `iv` | yes | base64url AES-GCM nonce |
| `kdfSalt` | no | base64url; present means a passphrase is required to decrypt |
| `verifier` | **yes** | base64url; lets the server refuse a wrong key without spending a view |
| `label` | no | `iv~ciphertext`, both base64url — encrypted like everything else |
| `ttl` | no | seconds, 60 to 2592000 (30 days). Default 86400 |
| `maxViews` | no | 1 to 10. Default 1, which is burn-after-reading |

```bash
curl -X POST 'https://secret.airat.top/api/secrets' \
  -H 'Content-Type: application/json' \
  -d '{
    "ciphertext": "mgN2vg9tjOmaRaaWVdshdklM0g8wRVA",
    "iv": "hMePPtwiYPR7hBdE",
    "verifier": "0Rk8yTn2wq7pQF3mJ1sX9dLbVhC5aZuEoNr4tGiKyPs",
    "ttl": 3600,
    "maxViews": 1
  }'
```

```json
{
  "id": "06G6822EJ5S7XCMAQKKQY1WC68",
  "url": "https://secret.airat.top/06G6822EJ5S7XCMAQKKQY1WC68",
  "burnToken": "6YZXI4ezPe0Ns64cDE3mYFapumrEmKCw",
  "expiresAt": 1788388261137,
  "maxViews": 1
}
```

The link to send is `url` with your key appended after a `#`. The `burnToken` is returned
here and never again — it is the creator's only proof, and a second way to fetch it would
make it derivable from the id.

### `GET /api/secrets/{id}`

What the landing page may know before anyone commits to opening the secret. **It does not
consume a view**, so a link previewer or a mail scanner following the URL cannot destroy a
secret before its recipient clicks.

```bash
curl 'https://secret.airat.top/api/secrets/06G6822EJ5S7XCMAQKKQY1WC68'
```

```json
{
  "id": "06G6822EJ5S7XCMAQKKQY1WC68",
  "hasPassword": false,
  "kdfSalt": null,
  "label": null,
  "maxViews": 1,
  "viewsLeft": 1,
  "sizeBytes": 31,
  "createdAt": 1788384661137,
  "expiresAt": 1788388261137
}
```

### `POST /api/secrets/{id}/reveal`

The only call with a side effect: it consumes one view, and deletes the secret when the
last one is used. `GET` here returns `405` rather than the ciphertext, deliberately.

Send the `verifier` for the key you hold. The server compares it and refuses a mismatch
with `403` **without spending a view**, so a wrong passphrase or a truncated link costs
nothing. It is optional, and secrets stored without one are not checked.

```bash
curl -X POST 'https://secret.airat.top/api/secrets/06G6822EJ5S7XCMAQKKQY1WC68/reveal' \
  -H 'Content-Type: application/json' \
  -d '{"verifier": "0Rk8yTn2wq7pQF3mJ1sX9dLbVhC5aZuEoNr4tGiKyPs"}'
```

```json
{
  "id": "06G6822EJ5S7XCMAQKKQY1WC68",
  "ciphertext": "mgN2vg9tjOmaRaaWVdshdklM0g8wRVA",
  "iv": "hMePPtwiYPR7hBdE",
  "kdfSalt": null,
  "label": null,
  "viewsLeft": 0,
  "burned": true,
  "expiresAt": 1788388261137
}
```

Asking again returns `404`. So does the metadata endpoint — and so does an id that was
never issued, or one that expired, with the same body in every case:

```json
{
  "error": "This secret does not exist, has expired, or has already been destroyed.",
  "code": "gone"
}
```

That sameness is deliberate. Telling the three apart would turn the endpoint into an
oracle for which identifiers were ever issued.

### `DELETE /api/secrets/{id}`

Destroys a secret before anyone reads it. Needs the burn token from creation; without it,
or with the wrong one, the answer is the same `404` as above.

```bash
curl -X DELETE 'https://secret.airat.top/api/secrets/06G6822EJ5S7XCMAQKKQY1WC68' \
  -H 'Content-Type: application/json' \
  -d '{"burnToken": "6YZXI4ezPe0Ns64cDE3mYFapumrEmKCw"}'
```

```json
{ "destroyed": true }
```

### `GET /api/config`

The limits the web UI validates against, so a client cannot offer what the server would
reject.

```bash
curl 'https://secret.airat.top/api/config'
```

```json
{
  "ttlOptions": [
    { "value": 86400, "label": "24 hours" },
    { "value": 3600, "label": "1 hour" },
    { "value": 300, "label": "5 minutes" },
    { "value": 604800, "label": "7 days" },
    { "value": 2592000, "label": "30 days" }
  ],
  "defaultTtl": 86400,
  "defaultMaxViews": 1,
  "maxViews": 10,
  "maxCiphertextBytes": 65536
}
```

### `GET /health`

```bash
curl 'https://secret.airat.top/health'
```

```json
{ "status": "ok", "database": "ok" }
```

Returns `503` with `"database": "unavailable"` when D1 cannot be reached, so a status
checker sees it as down. Status page: https://status.airat.top

### End to end from a script

Encryption is the caller's job, so a shell example needs a language with a crypto library.
This is the whole flow in Node, using this repository's own module:

```js
import { encryptText, decryptText } from "./public_html/crypto.js";

const BASE = "https://secret.airat.top";

// 1. Encrypt locally. `linkKey` must never be sent anywhere.
const enc = await encryptText("hunter2", null);

// 2. Store the ciphertext.
const created = await (
  await fetch(`${BASE}/api/secrets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ciphertext: enc.ciphertext,
      iv: enc.iv,
      verifier: enc.verifier,
      ttl: 3600,
      maxViews: 1
    })
  })
).json();

// 3. The link, assembled on this side. The fragment never leaves the client.
console.log(`${created.url}#${enc.linkKey}`);

// 4. The recipient consumes the view and decrypts.
const revealed = await (
  await fetch(`${BASE}/api/secrets/${created.id}/reveal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ verifier: enc.verifier })
  })
).json();
console.log(await decryptText(revealed.ciphertext, revealed.iv, enc.linkKey, null, revealed.kdfSalt));
// -> hunter2
```

### Errors

| Status | Meaning |
| --- | --- |
| `400` | The body is malformed, or a field is outside its limits |
| `403` | `/reveal` only: the verifier does not match. No view was spent — retry |
| `413` | Request body over 128 KB |
| `415` | Content-Type is not `application/json` |
| `429` | Rate limited. `Retry-After` says when to come back |
| `404` | Gone, expired, never issued, wrong burn token, or a malformed id |
| `405` | Wrong method — notably `GET` on `/reveal`, which has a side effect |
| `503` | `/health` only: D1 unreachable |

## Development

```sh
npm install
npx wrangler d1 create secret-airat     # copy database_id into wrangler.jsonc
npm run db:migrate:local
npm run dev
```

Running the tests and the type check:

```sh
npm test
npm run typecheck
```

They run in `workerd` against a real local D1 with the real migrations applied, because
the invariant most worth checking — a burn-after-reading link burns exactly once when two
readers arrive together — is a property of how D1 serialises a statement, and a mock would
prove nothing about it.

Deploying to production:

```sh
npm run db:migrate
npm run deploy
```

Pushes to `main` do both through `.github/workflows/deploy.yml`, which needs the
`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` repository secrets.

## Prior art

[OneTime Secret](https://onetimesecret.com/), [Yopass](https://yopass.se/),
[Password Pusher](https://pwpush.com/), [Hemmelig](https://github.com/HemmeligOrg/Hemmelig.app),
[SnapPass](https://github.com/pinterest/snappass), [PrivateBin](https://github.com/PrivateBin/PrivateBin),
and [Bitwarden Send](https://bitwarden.com/help/create-send/). The browser-side encryption
here follows Yopass and Hemmelig.

## Security

Reports go to [mail@airat.top](mailto:mail@airat.top), not to a public issue. What the
design does and does not protect against is written out in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Author

**AiratTop (Airat Halitov)**

- Website: [airat.top](https://airat.top)
- GitHub: [@AiratTop](https://github.com/AiratTop)
- Email: [mail@airat.top](mailto:mail@airat.top)
- Repository: [secret.airat.top](https://github.com/AiratTop/secret.airat.top)
