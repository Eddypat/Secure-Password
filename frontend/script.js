/* script.js
 * Client-side logic for Cipherkeep.
 * Talks to the Flask backend at /api/encrypt, /api/decrypt, /api/strength,
 * /api/encrypt-file and /api/decrypt-file. No cryptography happens here —
 * this file only handles UI state and network requests.
 */

const state = {
  dataMode: "text",   // 'text' | 'file'
  opMode: "encrypt",  // 'encrypt' | 'decrypt'
  selectedFile: null,
};

const el = (id) => document.getElementById(id);

const textLabel = el("textLabel");
const textInput = el("textInput");
const fileField = el("fileField");
const textField = el("textField");
const dropzone = el("dropzone");
const dzText = el("dzText");
const fileInput = el("fileInput");
const passwordInput = el("passwordInput");
const pwToggle = el("pwToggle");
const strengthFill = el("strengthFill");
const strengthLabel = el("strengthLabel");
const strengthTips = el("strengthTips");
const goBtn = el("goBtn");
const goBtnLabel = el("goBtnLabel");
const statusBox = el("statusBox");
const resultField = el("resultField");
const resultLabel = el("resultLabel");
const resultOutput = el("resultOutput");
const copyBtn = el("copyBtn");
const copiedTag = el("copiedTag");

/* ---------------- mode switching ---------------- */
document.querySelectorAll("#dataModeSeg .seg-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#dataModeSeg .seg-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    state.dataMode = btn.dataset.datamode;
    textField.classList.toggle("hidden", state.dataMode !== "text");
    fileField.classList.toggle("hidden", state.dataMode !== "file");
    hideResult();
  });
});

document.querySelectorAll("#opModeSeg .seg-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#opModeSeg .seg-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    state.opMode = btn.dataset.opmode;
    updateLabels();
    hideResult();
  });
});

function updateLabels() {
  const isEncrypt = state.opMode === "encrypt";
  textLabel.textContent = isEncrypt ? "Plaintext to seal" : "Ciphertext package to open";
  textInput.placeholder = isEncrypt
    ? "Type or paste the message you want to protect…"
    : "Paste the Base64 ciphertext package produced by Cipherkeep…";
  goBtnLabel.textContent = isEncrypt ? "Encrypt" : "Decrypt";
  resultLabel.textContent = isEncrypt ? "Ciphertext package" : "Recovered plaintext";
}

/* ---------------- file input ---------------- */
dropzone.addEventListener("click", () => fileInput.click());
["dragover", "dragenter"].forEach((evt) =>
  dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropzone.classList.add("drag");
  })
);
["dragleave", "drop"].forEach((evt) =>
  dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag");
  })
);
dropzone.addEventListener("drop", (e) => {
  const f = e.dataTransfer.files[0];
  if (f) setSelectedFile(f);
});
fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) setSelectedFile(fileInput.files[0]);
});
function setSelectedFile(file) {
  state.selectedFile = file;
  dzText.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
}

/* ---------------- password visibility ---------------- */
pwToggle.addEventListener("click", () => {
  const isPw = passwordInput.type === "password";
  passwordInput.type = isPw ? "text" : "password";
  pwToggle.textContent = isPw ? "\u{1F576}" : "\u{1F441}";
});

/* ---------------- password strength (debounced call to backend) ---------------- */
let strengthTimer = null;
passwordInput.addEventListener("input", () => {
  clearTimeout(strengthTimer);
  const pw = passwordInput.value;
  if (!pw) {
    strengthFill.style.width = "0%";
    strengthLabel.textContent = "";
    strengthTips.innerHTML = "";
    return;
  }
  strengthTimer = setTimeout(() => checkStrength(pw), 180);
});

async function checkStrength(password) {
  try {
    const res = await fetch("/api/strength", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    const data = await res.json();
    renderStrength(data);
  } catch (e) {
    // Fail silently for strength check — non-critical UX feature
  }
}

function renderStrength(data) {
  const colors = { Weak: "#c8664f", Fair: "#c9a24b", Strong: "#5fa89a", "Very Strong": "#6fd6b3" };
  strengthFill.style.width = `${data.score}%`;
  strengthFill.style.background = colors[data.label] || "#c8664f";
  strengthLabel.textContent = data.label;
  strengthTips.innerHTML = "";
  (data.feedback || []).slice(0, 3).forEach((tip) => {
    const li = document.createElement("li");
    li.textContent = tip;
    strengthTips.appendChild(li);
  });
}

/* ---------------- main action ---------------- */
goBtn.addEventListener("click", async () => {
  const password = passwordInput.value;
  if (!password) {
    showStatus("A password is required.", false);
    return;
  }

  goBtn.disabled = true;
  hideResult();
  hideStatus();

  try {
    if (state.dataMode === "text") {
      await handleTextOperation(password);
    } else {
      await handleFileOperation(password);
    }
  } catch (err) {
    showStatus(err.message || "Something went wrong.", false);
  } finally {
    goBtn.disabled = false;
  }
});

async function handleTextOperation(password) {
  const value = textInput.value.trim();
  if (!value) {
    showStatus(state.opMode === "encrypt" ? "Enter some text to encrypt." : "Paste a ciphertext package to decrypt.", false);
    return;
  }

  const endpoint = state.opMode === "encrypt" ? "/api/encrypt" : "/api/decrypt";
  const body =
    state.opMode === "encrypt" ? { plaintext: value, password } : { ciphertext: value, password };

  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();

  if (!res.ok) {
    showStatus(data.error || "Operation failed.", false);
    return;
  }

  const output = state.opMode === "encrypt" ? data.ciphertext : data.plaintext;
  showResult(output);
  showStatus(
    state.opMode === "encrypt" ? "Sealed successfully." : "Unsealed successfully — password verified.",
    true
  );
}

async function handleFileOperation(password) {
  if (!state.selectedFile) {
    showStatus("Choose a file first.", false);
    return;
  }

  const endpoint = state.opMode === "encrypt" ? "/api/encrypt-file" : "/api/decrypt-file";
  const form = new FormData();
  form.append("file", state.selectedFile);
  form.append("password", password);

  const res = await fetch(endpoint, { method: "POST", body: form });

  if (!res.ok) {
    let msg = "Operation failed.";
    try {
      const data = await res.json();
      msg = data.error || msg;
    } catch (_) {}
    showStatus(msg, false);
    return;
  }

  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^"]+)"?/);
  const filename = match ? match[1] : state.opMode === "encrypt" ? `${state.selectedFile.name}.enc` : "decrypted_file";

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);

  showStatus(
    state.opMode === "encrypt"
      ? `File encrypted and downloaded as "${filename}".`
      : `File decrypted and downloaded as "${filename}".`,
    true
  );
}

/* ---------------- helpers ---------------- */
function showStatus(msg, ok) {
  statusBox.textContent = msg;
  statusBox.classList.remove("hidden", "ok", "err");
  statusBox.classList.add(ok ? "ok" : "err");
}
function hideStatus() {
  statusBox.classList.add("hidden");
}
function showResult(text) {
  resultOutput.value = text;
  resultField.classList.remove("hidden");
}
function hideResult() {
  resultField.classList.add("hidden");
  copiedTag.classList.add("hidden");
}

copyBtn.addEventListener("click", async () => {
  await navigator.clipboard.writeText(resultOutput.value);
  copiedTag.classList.remove("hidden");
  setTimeout(() => copiedTag.classList.add("hidden"), 1800);
});

updateLabels();
