/**
 * The create page.
 *
 * The only thing worth watching in here: `linkKey` is produced by `encryptText`, written
 * into the fragment of the link shown to the user, and never put into a request body.
 */

import { encryptText, encryptWith } from "/crypto.js";

const els = {
  secret: document.getElementById("secretInput"),
  label: document.getElementById("labelInput"),
  ttl: document.getElementById("ttlSelect"),
  views: document.getElementById("viewsSelect"),
  passphrase: document.getElementById("passphraseInput"),
  create: document.getElementById("createButton"),
  createNotice: document.getElementById("createNotice"),
  composeCard: document.getElementById("composeCard"),
  resultCard: document.getElementById("resultCard"),
  resultLink: document.getElementById("resultLink"),
  resultMeta: document.getElementById("resultMeta"),
  resultNotice: document.getElementById("resultNotice"),
  copy: document.getElementById("copyButton"),
  burn: document.getElementById("burnButton"),
  again: document.getElementById("newButton"),
  sizeHint: document.getElementById("sizeHint")
};

let config = null;
let created = null; // { id, url, burnToken }

function notice(el, message, kind = "") {
  el.textContent = message;
  el.className = `notice ${kind}`.trim();
}

function formatDuration(seconds) {
  if (seconds % 86400 === 0) return `${seconds / 86400} day${seconds === 86400 ? "" : "s"}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? "" : "s"}`;
  return `${seconds / 60} minutes`;
}

/** The form's options come from the API so it cannot offer what the server would reject. */
async function loadConfig() {
  const response = await fetch("/api/config");
  config = await response.json();

  els.ttl.innerHTML = "";
  for (const option of config.ttlOptions) {
    const node = document.createElement("option");
    node.value = String(option.value);
    node.textContent = option.label;
    if (option.value === config.defaultTtl) node.selected = true;
    els.ttl.append(node);
  }

  els.views.innerHTML = "";
  for (const count of [1, 2, 3, 5, config.maxViews]) {
    if (count > config.maxViews) continue;
    const node = document.createElement("option");
    node.value = String(count);
    node.textContent = count === 1 ? "Once (burn after reading)" : `${count} times`;
    if (count === config.defaultMaxViews) node.selected = true;
    els.views.append(node);
  }
}

async function create() {
  const plaintext = els.secret.value;
  if (!plaintext.trim()) {
    notice(els.createNotice, "Nothing to share yet.", "error");
    return;
  }

  els.create.disabled = true;
  notice(els.createNotice, "Encrypting…");

  try {
    const passphrase = els.passphrase.value || null;
    const encrypted = await encryptText(plaintext, passphrase);

    const labelText = els.label.value.trim();
    const label = labelText
      ? await encryptWith(labelText, encrypted.linkKey, passphrase, encrypted.kdfSalt)
      : null;

    const response = await fetch("/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        kdfSalt: encrypted.kdfSalt,
        label,
        ttl: Number(els.ttl.value),
        maxViews: Number(els.views.value)
      })
    });

    const body = await response.json();
    if (!response.ok) {
      notice(els.createNotice, body.error ?? "Could not create the link.", "error");
      return;
    }

    // The key is appended here, in the browser, and only here.
    created = { ...body, url: `${body.url}#${encrypted.linkKey}` };
    showResult();
  } catch (err) {
    notice(els.createNotice, `Encryption failed: ${err.message}`, "error");
  } finally {
    els.create.disabled = false;
  }
}

function showResult() {
  els.resultLink.textContent = created.url;
  els.resultMeta.innerHTML = "";

  const items = [
    created.maxViews === 1 ? "Burns after one read" : `Opens up to ${created.maxViews} times`,
    `Expires ${new Date(created.expiresAt).toLocaleString()}`,
    els.passphrase.value ? "Passphrase required" : "Link only"
  ];
  for (const item of items) {
    const node = document.createElement("li");
    node.textContent = item;
    els.resultMeta.append(node);
  }

  els.composeCard.hidden = true;
  els.resultCard.hidden = false;
  notice(els.createNotice, "");

  // The plaintext has no reason to stay in the DOM once the link exists.
  els.secret.value = "";
  els.passphrase.value = "";
}

async function burn() {
  if (!created) return;
  const response = await fetch(`/api/secrets/${created.id}`, {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ burnToken: created.burnToken })
  });
  if (response.ok) {
    notice(els.resultNotice, "Destroyed. The link is dead.", "success");
    els.burn.disabled = true;
  } else {
    notice(els.resultNotice, "Already gone.", "error");
  }
}

els.create.addEventListener("click", create);
els.copy.addEventListener("click", async () => {
  await navigator.clipboard.writeText(created.url);
  notice(els.resultNotice, "Copied.", "success");
});
els.burn.addEventListener("click", burn);
els.again.addEventListener("click", () => {
  created = null;
  els.resultCard.hidden = true;
  els.composeCard.hidden = false;
  els.burn.disabled = false;
  notice(els.resultNotice, "");
});

els.secret.addEventListener("input", () => {
  if (!config) return;
  // Rough: base64 of AES-GCM output runs about 4/3 of the plaintext plus the tag.
  const estimate = Math.ceil((new TextEncoder().encode(els.secret.value).length + 16) * 1.34);
  els.sizeHint.textContent =
    estimate > config.maxCiphertextBytes
      ? "Too long — this is meant for credentials and notes, not files."
      : "Encrypted locally before anything is sent.";
  els.sizeHint.style.color = estimate > config.maxCiphertextBytes ? "var(--danger)" : "";
});

loadConfig().catch(() => notice(els.createNotice, "Could not reach the API.", "error"));
