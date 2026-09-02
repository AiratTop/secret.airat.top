# Third-Party Notices

This project bundles no third-party code: nothing from `node_modules` is served to a
browser, and the pages load only files from this repository. The following are used at
runtime or during development, under their own licenses.

## Fonts

- **Space Grotesk** — SIL Open Font License 1.1.
  https://github.com/floriankarsten/space-grotesk
- **JetBrains Mono** — SIL Open Font License 1.1.
  https://github.com/JetBrains/JetBrainsMono

Both are referenced from Google Fonts (https://fonts.google.com) and no font file is
stored in or redistributed from this repository.

In production the `airat.top` zone has Cloudflare Fonts enabled, which rewrites those
links into `@font-face` rules served from this origin — so the pages make no request to
Google, and the font files reach visitors from `secret.airat.top` rather than from
`fonts.gstatic.com`. Noted here because the delivered HTML says something different from
the source.

## Development dependencies

None of these reach a visitor; they build, test and deploy the project.

- **Wrangler** — Cloudflare's Workers CLI. MIT OR Apache-2.0.
  https://github.com/cloudflare/workers-sdk
- **@cloudflare/vitest-pool-workers** — runs the tests inside `workerd`. MIT.
  https://github.com/cloudflare/workers-sdk
- **@cloudflare/workers-types** — type definitions for the Workers runtime.
  MIT OR Apache-2.0. https://github.com/cloudflare/workerd
- **Vitest** — test runner. MIT. https://github.com/vitest-dev/vitest
- **TypeScript** — used for the test sources and type checking. Apache-2.0.
  https://github.com/microsoft/TypeScript

Apache-2.0 applies to this project's own code and documentation and does not relicense
any of the material listed above.
