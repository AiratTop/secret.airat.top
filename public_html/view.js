/**
 * The view page.
 *
 * Two fetches, and the order matters. `GET /api/secrets/{id}` asks whether the secret is
 * still there and whether it needs a passphrase — it consumes nothing, so a preview bot
 * that loads this page harms no one. `POST .../reveal` is the one that burns, and it only
 * runs when a person clicks.
 */

import { decryptText, decryptLabel } from "/crypto.js";

const els = {
  headline: document.getElementById("headline"),
  subtitle: document.getElementById("subtitle"),
  gateCard: document.getElementById("gateCard"),
  gateMeta: document.getElementById("gateMeta"),
  gateNotice: document.getElementById("gateNotice"),
  passphraseField: document.getElementById("passphraseField"),
  passphrase: document.getElementById("passphraseInput"),
  reveal: document.getElementById("revealButton"),
  secretCard: document.getElementById("secretCard"),
  secretLabel: document.getElementById("secretLabel"),
  secretOutput: document.getElementById("secretOutput"),
  secretNotice: document.getElementById("secretNotice"),
  copy: document.getElementById("copyButton"),
  goneCard: document.getElementById("goneCard"),
  goneMessage: document.getElementById("goneMessage")
};

const id = location.pathname.slice(1);
const linkKey = location.hash.slice(1);
let meta = null;

function notice(el, message, kind = "") {
  el.textContent = message;
  el.className = `notice ${kind}`.trim();
}

function showGone(message) {
  els.headline.textContent = "Nothing here";
  els.subtitle.textContent = "";
  els.gateCard.hidden = true;
  els.secretCard.hidden = true;
  els.goneCard.hidden = false;
  if (message) els.goneMessage.textContent = message;
}

async function load() {
  // No fragment means no key. The server could not help even if it wanted to.
  if (!linkKey) {
    showGone("This link is missing its key. The part after # is what decrypts the secret, and it was lost on the way here.");
    return;
  }

  const response = await fetch(`/api/secrets/${id}`);
  if (!response.ok) {
    showGone();
    return;
  }

  meta = await response.json();
  els.headline.textContent = "A secret is waiting for you";
  els.subtitle.textContent = meta.maxViews === 1
    ? "Opening it destroys it. Make sure you can store it somewhere first."
    : "It will be destroyed once it runs out of views or expires.";

  els.gateMeta.innerHTML = "";
  const items = [
    meta.maxViews === 1 ? "Burns after this read" : `${meta.viewsLeft} of ${meta.maxViews} views left`,
    `Expires ${new Date(meta.expiresAt).toLocaleString()}`
  ];
  for (const item of items) {
    const node = document.createElement("li");
    node.textContent = item;
    els.gateMeta.append(node);
  }

  els.passphraseField.hidden = !meta.hasPassword;
  els.gateCard.hidden = false;

  // The label is encrypted with the same key, so it can be shown before the reveal
  // without the server ever having known what it says.
  if (meta.label) {
    try {
      const label = await decryptLabel(meta.label, linkKey, null, meta.kdfSalt);
      if (label && !meta.hasPassword) els.subtitle.textContent = `“${label}” — ${els.subtitle.textContent}`;
    } catch {
      // A passphrase-protected label cannot be read yet. Not an error.
    }
  }
}

async function reveal() {
  els.reveal.disabled = true;
  notice(els.gateNotice, "Retrieving…");

  const response = await fetch(`/api/secrets/${id}/reveal`, { method: "POST" });
  if (!response.ok) {
    showGone();
    return;
  }

  const body = await response.json();

  try {
    const passphrase = meta.hasPassword ? els.passphrase.value : null;
    const plaintext = await decryptText(body.ciphertext, body.iv, linkKey, passphrase, body.kdfSalt);

    if (body.label) {
      try {
        const label = await decryptLabel(body.label, linkKey, passphrase, body.kdfSalt);
        if (label) els.secretLabel.textContent = label;
      } catch {
        /* the label is decoration; a failure here should not hide the secret */
      }
    }

    els.secretOutput.textContent = plaintext;
    els.gateCard.hidden = true;
    els.secretCard.hidden = false;
    notice(
      els.secretNotice,
      body.burned
        ? "This secret has been destroyed. Reloading this page will show nothing."
        : `${body.viewsLeft} view${body.viewsLeft === 1 ? "" : "s"} left.`,
      body.burned ? "success" : ""
    );
  } catch {
    // The view was already consumed by the time decryption failed — say so plainly,
    // because a wrong passphrase here is not a retryable mistake on a one-view secret.
    els.reveal.disabled = false;
    notice(
      els.gateNotice,
      meta.hasPassword
        ? "Wrong passphrase, or the link is incomplete. Note that this attempt used up a view."
        : "This link is incomplete and the secret cannot be decrypted.",
      "error"
    );
  }
}

els.reveal.addEventListener("click", reveal);
els.copy.addEventListener("click", async () => {
  await navigator.clipboard.writeText(els.secretOutput.textContent);
  notice(els.secretNotice, "Copied.", "success");
});

load().catch(() => showGone("Could not reach the server."));
