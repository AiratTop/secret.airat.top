import type { D1Migration } from "cloudflare:test";

declare module "cloudflare:test" {
  interface ProvidedEnv {
    DB: D1Database;
    ASSETS: Fetcher;
    SITE_HOST: string;
    /** Supplied by vitest.config.ts, read out of the real `migrations/` directory. */
    TEST_MIGRATIONS: D1Migration[];
  }
}
