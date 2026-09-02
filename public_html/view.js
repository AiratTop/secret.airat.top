/**
 * The view page.
 *
 * Two fetches, and the order matters. `GET /api/secrets/{id}` asks whether the secret is
 * still there and whether it needs a passphrase — it consumes nothing, so a preview bot
 * that loads this page harms no one. `POST .../reveal` is the one that burns, and it only
 * runs when a person clicks.
 */

import { decryptText, decryptLabel, deriveVerifier } from "/crypto.js";
import { formatDateTime, formatRelative } from "/format.js";

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
  secretBlock: document.getElementById("secretBlock"),
  secretOutput: document.getElementById("secretOutput"),
  secretCopyState: document.getElementById("secretCopyState"),
  secretNotice: document.getElementById("secretNotice"),
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
    meta.maxViews === 1
      ? ["Burns after", "this read"]
      : ["Views left", `${meta.viewsLeft} of ${meta.maxViews}`],
    ["Expires", `${formatDateTime(meta.expiresAt)} · ${formatRelative(meta.expiresAt)}`]
  ];
  for (const [caption, value] of items) {
    const node = document.createElement("li");
    node.append(`${caption} `);
    const strong = document.createElement("b");
    strong.textContent = value;
    node.append(strong);
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
  const passphrase = meta.hasPassword ? els.passphrase.value : null;

  // Never sent at all when the box is empty. The server cannot judge a passphrase, so a
  // request it cannot satisfy is a request worth not making — and this was the shortest
  // path to destroying a one-view secret: open the link, click, read the prompt.
  if (meta.hasPassword && !passphrase) {
    notice(els.gateNotice, "This secret needs its passphrase before it can be opened.", "error");
    els.passphrase.focus();
    return;
  }

  els.reveal.disabled = true;
  notice(els.gateNotice, "Retrieving…");

  // Proves we hold the right key without disclosing it, so the server can refuse without
  // spending a view.
  const verifier = await deriveVerifier(linkKey, passphrase, meta.kdfSalt);

  const response = await fetch(`/api/secrets/${id}/reveal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ verifier })
  });

  if (response.status === 403) {
    els.reveal.disabled = false;
    notice(
      els.gateNotice,
      meta.hasPassword
        ? "Wrong passphrase. Nothing was used up — try again."
        : "This link is incomplete, so the secret cannot be decrypted. No view was used.",
      "error"
    );
    if (meta.hasPassword) els.passphrase.select();
    return;
  }

  if (!response.ok) {
    showGone();
    return;
  }

  const body = await response.json();

  try {
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
    // Reaching here means the server accepted the verifier and the ciphertext still would
    // not open, which a matching key should make impossible. It remains reachable for
    // secrets created before verifiers existed: those carry none, the server cannot
    // refuse, and the view is gone.
    els.reveal.disabled = false;
    notice(
      els.gateNotice,
      meta.hasPassword
        ? "Wrong passphrase, or the link is incomplete. This secret predates the check that would have caught it without using a view."
        : "This link is incomplete and the secret cannot be decrypted.",
      "error"
    );
  }
}

let copyResetTimer = null;

/**
 * Copies the whole secret, unless the reader was in the middle of selecting part of it —
 * a click that ends a drag-selection means "I want this bit", and overwriting the
 * clipboard with everything would be the opposite of what was asked.
 */
async function copySecret() {
  if (String(getSelection() ?? "").length > 0) return;

  try {
    await navigator.clipboard.writeText(els.secretOutput.textContent);
    els.secretBlock.classList.add("is-copied");
    els.secretCopyState.textContent = "Copied";
    clearTimeout(copyResetTimer);
    copyResetTimer = setTimeout(() => {
      els.secretBlock.classList.remove("is-copied");
      els.secretCopyState.textContent = "Click to copy";
    }, 2500);
  } catch {
    // A refused clipboard permission is not a failure to report as an error — the text is
    // right there and selectable.
    els.secretCopyState.textContent = "Press ⌘C / Ctrl+C to copy";
  }
}

els.reveal.addEventListener("click", reveal);
els.secretBlock.addEventListener("click", copySecret);
els.secretBlock.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    copySecret();
  }
});

load().catch(() => showGone("Could not reach the server."));
