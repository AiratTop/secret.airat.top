/**
 * Dates, in one place and in one format: `2026-09-03 23:38`.
 *
 * ISO order and a 24-hour clock, rather than `toLocaleString`'s default — which renders
 * "9/3/2026, 11:38:09 PM" for one reader and "03.09.2026, 23:38" for the next. An expiry
 * is a deadline someone has to act on, and a date whose meaning depends on where the
 * reader is sitting is a bad way to state one. The values are still local time, since
 * that is the clock the reader is actually looking at.
 */
/** @param {number} ms */
export function formatDateTime(ms) {
  const d = new Date(ms);
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    ` ${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

/**
 * "in 3 days", "in 4 hours" — the part a reader actually wants from an expiry. Shown next
 * to the timestamp rather than instead of it, because "in 4 hours" is unusable for
 * anything you have to plan around and the timestamp alone takes a moment to subtract.
 */
/**
 * @param {number} ms
 * @param {number} [now]
 */
export function formatRelative(ms, now = Date.now()) {
  const seconds = Math.round((ms - now) / 1000);
  if (seconds <= 0) return "expired";

  // Annotated: without it these read as (string | number)[] pairs and the arithmetic
  // below is comparing a number against something that might be a word.
  /** @type {[string, number][]} */
  const units = [
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60]
  ];
  for (const [name, size] of units) {
    if (seconds >= size) {
      const value = Math.round(seconds / size);
      return `in ${value} ${name}${value === 1 ? "" : "s"}`;
    }
  }
  return "in under a minute";
}
