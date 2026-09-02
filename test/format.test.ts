import { describe, it, expect } from "vitest";
import { formatDateTime, formatRelative } from "../public_html/format.js";

describe("timestamps", () => {
  /**
   * The reason this exists instead of `toLocaleString`, which renders the same instant as
   * "9/3/2026, 11:38:09 PM" for one reader and "03.09.2026, 23:38" for the next.
   */
  it("writes ISO order and a 24-hour clock", () => {
    expect(formatDateTime(Date.parse("2026-09-03T23:38:09"))).toBe("2026-09-03 23:38");
    expect(formatDateTime(Date.parse("2026-09-03T00:05:00"))).toBe("2026-09-03 00:05");
    expect(formatDateTime(Date.parse("2026-09-03T12:00:00"))).toBe("2026-09-03 12:00");
  });

  it("pads single-digit months, days, hours and minutes", () => {
    expect(formatDateTime(Date.parse("2026-01-05T04:07:00"))).toBe("2026-01-05 04:07");
  });
});

describe("relative expiry", () => {
  const now = Date.parse("2026-09-03T12:00:00");

  it("picks the largest unit that fits", () => {
    expect(formatRelative(now + 7 * 86400e3, now)).toBe("in 7 days");
    expect(formatRelative(now + 86400e3, now)).toBe("in 1 day");
    expect(formatRelative(now + 3600e3, now)).toBe("in 1 hour");
    expect(formatRelative(now + 4 * 3600e3, now)).toBe("in 4 hours");
    expect(formatRelative(now + 300e3, now)).toBe("in 5 minutes");
    expect(formatRelative(now + 60e3, now)).toBe("in 1 minute");
  });

  it("does not claim a deadline that has passed is still ahead", () => {
    expect(formatRelative(now + 30e3, now)).toBe("in under a minute");
    expect(formatRelative(now, now)).toBe("expired");
    expect(formatRelative(now - 86400e3, now)).toBe("expired");
  });
});
