/**
 * Per-caller flood protection, counted somewhere that actually counts.
 *
 * This started as Cloudflare's rate limit binding, which is the documented answer and is
 * three lines. It enforces, but loosely: measured against the deployed Worker with the
 * binding set to 3 requests a minute, 23 of 39 consecutive calls under one key were
 * allowed before it began refusing. That is the documented behaviour rather than a fault
 * — "permissive, eventually consistent, and intentionally designed to not be used as an
 * accurate accounting system" — and it is the wrong shape here, because a burst is
 * precisely what fills a database, and the burst is what slips through before the count
 * propagates.
 *
 * One object per key, addressed by `idFromName`, so "ten writes a minute" means ten —
 * not ten per data centre, which is the accuracy the binding trades away.
 *
 * The count lives in memory rather than in storage. An object is evicted when idle, which
 * resets its window and makes the limiter permissive for someone who stopped and came
 * back. That is the harmless direction: a caller flooding keeps their own object alive,
 * which is precisely the case this exists for, and the alternative is a storage write on
 * every request to defend against nobody.
 */
export class RateLimiter {
  constructor() {
    this.window = -1;
    this.count = 0;
  }

  async fetch(request) {
    const { limit, periodSeconds } = await request.json();

    const periodMs = periodSeconds * 1000;
    const now = Date.now();
    const window = Math.floor(now / periodMs);

    if (window !== this.window) {
      this.window = window;
      this.count = 0;
    }
    this.count += 1;

    const allowed = this.count <= limit;
    const retryAfter = Math.max(1, Math.ceil(((window + 1) * periodMs - now) / 1000));

    return Response.json({ allowed, retryAfter });
  }
}
