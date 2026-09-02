/**
 * Every D1 statement this Worker runs.
 *
 * Kept in one file so the handlers stay about HTTP and the invariants that matter — a
 * secret is never served after it expires, and never served more times than it was
 * allowed — live in exactly one place.
 */

/**
 * Stores a new secret. The caller has already validated and generated the id.
 */
export async function insertSecret(db, secret) {
  await db
    .prepare(
      `INSERT INTO secrets
         (id, ciphertext, iv, kdf_salt, label, max_views, views, size_bytes, created_at, expires_at, burn_token)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`
    )
    .bind(
      secret.id,
      secret.ciphertext,
      secret.iv,
      secret.kdfSalt ?? null,
      secret.label ?? null,
      secret.maxViews,
      secret.sizeBytes,
      secret.createdAt,
      secret.expiresAt,
      secret.burnToken
    )
    .run();
}

/**
 * What the landing page is allowed to know before anyone commits to opening the secret.
 *
 * Deliberately not the ciphertext: `GET /{id}` is fetched by link previewers, antivirus
 * scanners and chat clients that unfurl URLs, and if that fetch consumed a view the
 * secret would be burned before its recipient ever clicked. Revealing is a POST the
 * reader has to ask for.
 */
export async function getSecretMeta(db, id, now) {
  const row = await db
    .prepare(
      `SELECT id, kdf_salt, label, max_views, views, size_bytes, created_at, expires_at
         FROM secrets
        WHERE id = ? AND expires_at > ?`
    )
    .bind(id, now)
    .first();

  if (!row) return null;
  return {
    id: row.id,
    hasPassword: row.kdf_salt !== null,
    kdfSalt: row.kdf_salt,
    label: row.label,
    maxViews: row.max_views,
    viewsLeft: row.max_views - row.views,
    sizeBytes: row.size_bytes,
    createdAt: row.created_at,
    expiresAt: row.expires_at
  };
}

/**
 * Consumes one view and returns the ciphertext, or null if there was nothing left to give.
 *
 * The counter is incremented in the same statement that selects the row, with the
 * remaining-views and expiry conditions in its WHERE. That is what makes a burn-after-
 * reading link actually burn once: two simultaneous readers both run this UPDATE, D1
 * serialises them, and the second one matches no row because `views < max_views` is no
 * longer true. Reading and then writing would hand the secret to both of them.
 */
export async function consumeSecret(db, id, now) {
  const row = await db
    .prepare(
      `UPDATE secrets
          SET views = views + 1
        WHERE id = ? AND expires_at > ? AND views < max_views
        RETURNING id, ciphertext, iv, kdf_salt, label, max_views, views, expires_at`
    )
    .bind(id, now)
    .first();

  if (!row) return null;

  const exhausted = row.views >= row.max_views;
  // The row has given up everything it had. Deleting it now rather than leaving it for the
  // cron is the difference between "burned" meaning gone and meaning unreadable-for-now.
  if (exhausted) await deleteSecret(db, id);

  return {
    id: row.id,
    ciphertext: row.ciphertext,
    iv: row.iv,
    kdfSalt: row.kdf_salt,
    label: row.label,
    viewsLeft: Math.max(0, row.max_views - row.views),
    burned: exhausted,
    expiresAt: row.expires_at
  };
}

export async function deleteSecret(db, id) {
  await db.prepare(`DELETE FROM secrets WHERE id = ?`).bind(id).run();
}

/**
 * Early destruction by the creator, who is the only party holding the burn token.
 * Returns whether a row was actually removed, so the UI can tell "destroyed" from
 * "already gone".
 */
export async function burnSecret(db, id, burnToken) {
  const result = await db
    .prepare(`DELETE FROM secrets WHERE id = ? AND burn_token = ?`)
    .bind(id, burnToken)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

/**
 * The cron sweep. Expiry is enforced on every read too, so this is housekeeping rather
 * than a correctness guarantee — an expired row is already invisible before it is deleted.
 * Batched because D1 would rather run a bounded DELETE every fifteen minutes than an
 * unbounded one after an outage.
 */
export async function deleteExpired(db, now, limit = 1000) {
  const result = await db
    .prepare(`DELETE FROM secrets WHERE id IN (SELECT id FROM secrets WHERE expires_at <= ? LIMIT ?)`)
    .bind(now, limit)
    .run();
  return result.meta?.changes ?? 0;
}
