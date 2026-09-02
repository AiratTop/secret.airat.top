# Contributing

Thank you for your interest in improving secret.airat.top. Contributions of all kinds are welcome, including bug reports, documentation improvements, and UI or UX polish.

## How to Help

- **Report bugs or suggest enhancements** by opening an issue on GitHub. Please include clear reproduction steps, your browser and OS, and any console errors.
- **Improve documentation** by fixing typos or clarifying usage details in the README.
- **Submit pull requests** for the Worker, the pages, accessibility, or performance.

## Before You Start

- Read the repository `README.md` for what the project does, and `AGENTS.md` for the decisions behind it.
- Keep changes focused. If you have multiple unrelated ideas, open separate pull requests.
- Add no external services, trackers, or third-party scripts. There are none today, and that is deliberate — see below.

## The One Rule

The server must never be able to read a secret. The key is generated in the browser and lives in the URL fragment, which browsers never send to the origin; the Worker, its database, its logs and its backups hold only ciphertext.

A change that puts key material or plaintext into a request body, a log line, a database column, or a third-party script breaks the only guarantee this project makes, however convenient it looks. `gtag` reporting `location.href` is the specific reason there is no analytics on any page.

## Development Workflow

1. Fork the repository and clone your fork locally.
2. Create a feature branch that describes your work (for example, `feature/better-copy-feedback`).
3. Install dependencies with `npm install`.
4. Create a local database and apply the schema:

   ```sh
   npx wrangler d1 create secret-airat   # first time only; copy database_id into wrangler.jsonc
   npm run db:migrate:local
   ```

5. Run the site with `npm run dev`. Opening `public_html/index.html` from disk will not work — the pages need the Worker for `/api` and for `/{id}`.
6. Run `npm test` before opening a pull request.
7. Open a pull request against the `main` branch and describe what changed and how you verified it.

## Pull Request Checklist

- [ ] `npm test` passes.
- [ ] Behaviour was checked against `npm run dev`, not only in tests.
- [ ] No console errors in the browser.
- [ ] UI changes behave well on small screens and in both colour schemes.
- [ ] No new third-party request from any page.
- [ ] Documentation updated if user-facing behaviour changed.

## Tests

The suite runs in `workerd` against a real local D1 with the real migrations applied, because the invariants worth protecting are properties of the database rather than of readable code — chiefly that a burn-after-reading link burns exactly once when two readers arrive together.

If you change how a secret is stored, read, or destroyed, add a test that fails without your change.

## Code Style and Standards

- Vanilla JavaScript and CSS, matching the existing style. No framework, no build step for the pages.
- Prefer accessibility-friendly patterns (keyboard use, contrast, focus states).
- Comments should say why, not what.

## Security and Responsible Disclosure

If you discover a security vulnerability, please do not open a public issue. See [SECURITY.md](../SECURITY.md), or email [mail@airat.top](mailto:mail@airat.top) with the details so it can be addressed promptly.

## Questions or Feedback

If you are unsure about anything before contributing, feel free to open a discussion or contact AiratTop at [mail@airat.top](mailto:mail@airat.top). Thanks.
