# secret.airat.top

Share secrets with self-destructing links.

A password, a token, or a note is encrypted in your browser, stored as ciphertext, and
handed over as a link that destroys itself — after one read by default, or when its timer
runs out.

**Live:** https://secret.airat.top

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

## API

| Method | Path | Effect |
| --- | --- | --- |
| `POST` | `/api/secrets` | Store ciphertext, get an id, URL and burn token |
| `GET` | `/api/secrets/{id}` | Metadata only — does not consume a view |
| `POST` | `/api/secrets/{id}/reveal` | Consume a view and return the ciphertext |
| `DELETE` | `/api/secrets/{id}` | Destroy early; needs the burn token |
| `GET` | `/api/config` | Limits the UI validates against |
| `GET` | `/health` | Liveness, including a D1 round trip |

Revealing is a `POST` so that link previewers, mail scanners and chat clients that unfurl
URLs cannot burn a secret before its recipient sees it.

## Development

```sh
npm install
npx wrangler d1 create secret-airat     # copy database_id into wrangler.jsonc
npm run db:migrate:local
npm run dev
```

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

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
