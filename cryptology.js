// Full functionality: RSA, Polybius, Vigenère (with ROT and HTML table), Caesar.
// Fixes:
// - UA_LO corrected (matched order to UA_UP)
// - Caesar: hardened shift parsing, no "undefined" output
// - Vigenère: render nice HTML table (vig-table), no references to missing textarea
// - RSA: auto-normalize M/C into range modulo N with clear logs

const EN_UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const EN_LO = "abcdefghijklmnopqrstuvwxyz";
const UA_UP = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ";
// Correct lowercase order to mirror UA_UP
const UA_LO = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя";

// Helpers
const byId = (id) => document.getElementById(id);
const appendLog = (boxId, msg) => {
  const el = byId(boxId);
  if (el) el.value = (el.value ? el.value + "\n" : "") + msg;
};

// ---------- Math (BigInt) ----------
function egcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}
function modinv(a, m) {
  const [g, x] = egcd(a, m);
  if (g !== 1n) throw new Error("No modular inverse (gcd != 1)");
  return ((x % m) + m) % m;
}
function modPow(base, exp, mod) {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

// ---------- Core helpers ----------
function rotateAlphabet(alpha, rot) {
  if (!alpha) return alpha;
  rot = ((rot % alpha.length) + alpha.length) % alpha.length;
  return alpha.slice(rot) + alpha.slice(0, rot);
}
function vigenere(text, key, encrypt, up) {
  if (!key) throw new Error("Key required");
  const keyUp = key.toUpperCase();
  for (const ch of keyUp) if (!up.includes(ch)) throw new Error("Key contains invalid characters");
  const out = [];
  let ki = 0;
  const n = up.length;
  for (const ch of text) {
    const cu = ch.toUpperCase();
    if (up.includes(cu)) {
      const tp = up.indexOf(cu), kp = up.indexOf(keyUp[ki % keyUp.length]);
      const rp = encrypt ? (tp + kp) % n : (tp - kp + n) % n;
      const rc = up[rp];
      out.push(ch === ch.toUpperCase() ? rc : rc.toLowerCase());
      ki++;
    } else out.push(ch);
  }
  return out.join("");
}

// ---------- Vigenère HTML table ----------
function vigenereRows(text, key, up) {
  if (!key) throw new Error("Key required");
  const keyUp = key.toUpperCase();
  for (const ch of keyUp) if (!up.includes(ch)) throw new Error("Key contains invalid characters");
  const n = up.length;
  const rows = [];
  let ki = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i], cu = ch.toUpperCase();
    if (up.includes(cu)) {
      const kch = keyUp[ki % keyUp.length], shift = up.indexOf(kch);
      const encPos = (up.indexOf(cu) + shift) % n, encCh = up[encPos];
      rows.push({
        idx: i + 1,
        orig: ch,
        key: (ch === ch.toUpperCase() ? kch : kch.toLowerCase()),
        shift,
        enc: (ch === ch.toUpperCase() ? encCh : encCh.toLowerCase()),
      });
      ki++;
    } else {
      rows.push({ idx: i + 1, orig: ch, key: "-", shift: "-", enc: ch });
    }
  }
  return rows;
}
function renderVigTable(rows) {
  const table = byId("vig-table");
  if (!table) return;
  const tbody = table.querySelector("tbody");
  tbody.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    ["idx", "orig", "key", "shift", "enc"].forEach((k) => {
      const td = document.createElement("td");
      td.textContent = r[k];
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  }
}

// ---------- Caesar (Cipser) ----------
function caesar(text, shift, up, lo) {
  const n = up.length;
  let s = Number.isFinite(shift) ? Math.trunc(shift) : 0;
  s = ((s % n) + n) % n; // normalize

  let out = "";
  for (const ch of text) {
    const U = up.indexOf(ch);
    if (U >= 0) {
      out += up[(U + s) % n];
      continue;
    }
    const L = lo.indexOf(ch);
    if (L >= 0) {
      out += lo[(L + s) % n];
      continue;
    }
    out += ch; // keep as-is
  }
  return out;
}

// ---------- RSA ----------
function intval(s) {
  s = String(s).trim();
  return s && /^-?\d+$/.test(s) ? BigInt(s) : null;
}
function requireInt(s, name) {
  s = String(s).trim();
  if (!s || !/^-?\d+$/.test(s)) throw new Error(`${name} must be integer`);
  return BigInt(s);
}

function rsaCompute() {
  try {
    const p = requireInt(byId("rsa-p").value, "p");
    const q = requireInt(byId("rsa-q").value, "q");
    if (p <= 1n || q <= 1n) throw new Error("p,q must be > 1");
    const N = p * q, phi = (p - 1n) * (q - 1n);

    let d = intval(byId("rsa-d").value);
    let e = intval(byId("rsa-e").value);
    if (d === null && e === null) throw new Error("Provide at least d or e");
    if (d !== null && e === null) e = modinv((d % phi + phi) % phi, phi);
    else if (e !== null && d === null) d = modinv((e % phi + phi) % phi, phi);
    else if ((e * d) % phi !== 1n) throw new Error("e and d are not modular inverses modulo φ(N)");

    const text = [
      `d = ${d}`, `e = ${e}`, `p = ${p}`, `q = ${q}`,
      `N = ${N}`, `φ(N) = ${phi}`, `Ek = (${e}, ${N})`, `Dk = (${d}, ${N})`
    ].join("\n");
    byId("rsa-params").value = text;
    appendLog("rsa-log", "Computed RSA parameters");
  } catch (exc) {
    appendLog("rsa-log", `Compute error: ${exc.message ?? exc}`);
    alert(`RSA compute: ${exc.message ?? exc}`);
  }
}

function rsaEncrypt() {
  try {
    const p = requireInt(byId("rsa-p").value, "p");
    const q = requireInt(byId("rsa-q").value, "q");
    const N = p * q;

    const e = intval(byId("rsa-e").value);
    if (e === null) throw new Error("e is required or compute first");

    let M = requireInt(byId("rsa-M").value, "M");
    if (M < 0n) throw new Error("M must be non-negative");
    if (M >= N) {
      const M0 = M;
      M = M % N;
      appendLog("rsa-log", `Note: M normalized modulo N (${M0} → ${M})`);
    }

    const C = modPow(M, e, N);
    const prev = byId("rsa-params").value.trim();
    byId("rsa-params").value = prev + `\n\nEncrypt:\nM = ${M}\nC = ${C}\n`;
    appendLog("rsa-log", `Encryption done. C=${C}`);
  } catch (exc) {
    appendLog("rsa-log", `Encrypt error: ${exc.message ?? exc}`);
    alert(`RSA encrypt: ${exc.message ?? exc}`);
  }
}

function rsaDecrypt() {
  try {
    const p = requireInt(byId("rsa-p").value, "p");
    const q = requireInt(byId("rsa-q").value, "q");
    const N = p * q;

    const d = intval(byId("rsa-d").value);
    if (d === null) throw new Error("d is required or compute first");

    let C = requireInt(byId("rsa-C").value, "C");
    if (C < 0n) throw new Error("C must be non-negative");
    if (C >= N) {
      const C0 = C;
      C = C % N;
      appendLog("rsa-log", `Note: C normalized modulo N (${C0} → ${C})`);
    }

    const M = modPow(C, d, N);
    const prev = byId("rsa-params").value.trim();
    byId("rsa-params").value = prev + `\n\nDecrypt:\nC = ${C}\nM = ${M}\n`;
    appendLog("rsa-log", `Decryption done. M=${M}`);
  } catch (exc) {
    appendLog("rsa-log", `Decrypt error: ${exc.message ?? exc}`);
    alert(`RSA decrypt: ${exc.message ?? exc}`);
  }
}

// ---------- Polybius ----------
function polyAlpha(kind) {
  return kind === "EN" ? "ABCDEFGHIKLMNOPQRSTUVWXYZ" : UA_UP + "012";
}
function polyMaps(alphabet) {
  const s = [...new Set(alphabet)].join("");
  const size = (s.length === 25) ? 5 : 6;
  const enc = {}, dec = {};
  let idx = 0;
  for (let r = 1; r <= size; r++) for (let c = 1; c <= size; c++) {
    const ch = s[idx++];
    enc[ch] = `${r}${c}`;
    dec[`${r}${c}`] = ch;
  }
  return [enc, dec];
}
function polyRun(encrypt) {
  try {
    const alpha = polyAlpha(byId("poly-alpha").value);
    const text = byId("poly-in").value;
    const [enc, dec] = polyMaps(alpha);
    let res;
    if (encrypt) {
      const out = [];
      for (const ch of text) {
        const cu = ch.toUpperCase();
        out.push(enc[cu] ?? ch);
      }
      res = out.join(" ").replace(/  +/g, " ");
    } else {
      const tokens = text.replace(/\n/g, " ").split(/\s+/);
      res = tokens.map((t) => dec[t] ?? t).join("");
    }
    byId("poly-out").value = res;
    appendLog("poly-log", "Done Polybius.");
  } catch (e) {
    appendLog("poly-log", `Polybius error: ${e.message ?? e}`);
    alert(`Polybius: ${e.message ?? e}`);
  }
}

// ---------- Vigenère actions ----------
function vigAlph() { return (byId("vig-alpha").value === "UA") ? [UA_UP, UA_LO] : [EN_UP, EN_LO]; }
function vigRotVal(up) {
  const s = byId("vig-rot").value.trim();
  if (/^-?\d+$/.test(s)) {
    const val = parseInt(s, 10);
    // invert sign to match desktop note
    return ((-val % up.length) + up.length) % up.length;
  }
  return 0;
}
function vigRun(encrypt) {
  try {
    const [up] = vigAlph();
    const rot = vigRotVal(up);
    const upR = rotateAlphabet(up, rot);
    const text = byId("vig-in").value;
    const key = byId("vig-key").value.trim();
    const res = vigenere(text, key, encrypt, upR);
    byId("vig-out").value = res;
    appendLog("vig-log", "Vigenère done");
  } catch (e) {
    appendLog("vig-log", `Error: ${e.message ?? e}`);
    alert(`Vigenère: ${e.message ?? e}`);
  }
}
function vigGenTable() {
  try {
    const [up] = vigAlph();
    const rot = vigRotVal(up);
    const upR = rotateAlphabet(up, rot);
    const text = byId("vig-in").value;
    const key = byId("vig-key").value.trim();
    const rows = vigenereRows(text, key, upR);
    renderVigTable(rows);
    appendLog("vig-log", `Table generated (ROT=${rot}) with ${rows.length} rows`);
  } catch (e) {
    appendLog("vig-log", `Table error: ${e.message ?? e}`);
    alert(`Vigenère table: ${e.message ?? e}`);
  }
}
function vigCopyTable() {
  try {
    const tbody = byId("vig-table").querySelector("tbody");
    const lines = [["#", "Orig", "Key", "Shift", "Enc"].join("\t")];
    for (const tr of tbody.querySelectorAll("tr")) {
      const cells = [...tr.querySelectorAll("td")].map((td) => td.textContent);
      lines.push(cells.join("\t"));
    }
    navigator.clipboard.writeText(lines.join("\n"));
    appendLog("vig-log", "Table copied (TSV) to clipboard");
  } catch (e) {
    appendLog("vig-log", `Copy error: ${e.message ?? e}`);
    alert(`Copy: ${e.message ?? e}`);
  }
}

// ---------- Cipser (Caesar) actions ----------
function cipRun(encrypt) {
  try {
    const useUA = byId("cip-alpha").value === "UA";
    const up = useUA ? UA_UP : EN_UP;
    const lo = useUA ? UA_LO : EN_LO;

    const raw = byId("cip-shift").value;
    const shift = /^-?\d+$/.test(String(raw).trim())
      ? parseInt(String(raw).trim(), 10)
      : 0;

    const text = byId("cip-in").value;
    const res = caesar(text, encrypt ? shift : -shift, up, lo);
    byId("cip-out").value = res;
    appendLog("cip-log", "Cipser done");
  } catch (e) {
    appendLog("cip-log", `Cipser error: ${e.message ?? e}`);
    alert(`Cipser: ${e.message ?? e}`);
  }
}

// ---------- Navigation & bindings ----------
function setupNav() {
  document.querySelectorAll("button[data-page]").forEach((btn) => {
    btn.addEventListener("click", () => showPage(btn.dataset.page));
  });
  showPage("rsa"); // default
}
function showPage(key) {
  document.querySelectorAll("section[id^='page-']").forEach((sec) => (sec.hidden = true));
  const el = byId(`page-${key}`);
  if (el) el.hidden = false;
}
function bindActions() {
  byId("btn-rsa-compute").addEventListener("click", rsaCompute);
  byId("btn-rsa-enc").addEventListener("click", rsaEncrypt);
  byId("btn-rsa-dec").addEventListener("click", rsaDecrypt);

  byId("btn-poly-enc").addEventListener("click", () => polyRun(true));
  byId("btn-poly-dec").addEventListener("click", () => polyRun(false));

  byId("btn-vig-enc").addEventListener("click", () => vigRun(true));
  byId("btn-vig-dec").addEventListener("click", () => vigRun(false));
  byId("btn-vig-tbl-gen").addEventListener("click", vigGenTable);
  byId("btn-vig-tbl-copy").addEventListener("click", vigCopyTable);

  byId("btn-cip-enc").addEventListener("click", () => cipRun(true));
  byId("btn-cip-dec").addEventListener("click", () => cipRun(false));
}
document.addEventListener("DOMContentLoaded", () => {
  setupNav();
  bindActions();
  appendLog("rsa-log", "Ready: RSA");
  appendLog("poly-log", "Ready: Polybius");
  appendLog("vig-log", "Ready: Vigenère");
  appendLog("cip-log", "Ready: Cipser");
});
