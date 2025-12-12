// Web port of lite.py functionality: RSA, Polybius, Vigenère (with ROT and table), Caesar.
// Includes UA/EN localization, theme apply, status logs.

const APP_VERSION = "Lite-1.7.2-compact";
const EN_UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const EN_LO = "abcdefghijklmnopqrstuvwxyz";
const UA_UP = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ";
const UA_LO = "абвгґдеєжзиіїйклмнопруфхцчшщьюя";

const THEMES = { "Нічна Прохолода": { class: "" }, "Світанок": { class: "theme-light" } };

const LANG = {
  ua: {
    title: "ДЕКРИПТОІНАТОР LITE",
    nav: ["RSA", "Полібій", "Віженер", "Cipser", "Налаштування", "Про автора"],
    log_title: "Логи:",
    rsa_title: "RSA — Завдання 4",
    rsa_desc: "Відомі: d або e, p, q. Обчислити N, φ(N), e, Ek, Dk. Шифрувати M, Дешифрувати C.",
    rsa_labels: { d: "d (приватний, optional):", e: "e (публічний, optional):", p: "p:", q: "q:", M: "M:", C: "C:" },
    rsa_actions: { compute: "Обчислити", enc: "Зашифрувати M → C", dec: "Розшифрувати C → M" },
    rsa_params: "Параметри (N, φ(N), e, Ek, Dk):",
    poly_title: "Квадрат Полібія",
    poly_alpha: "Алфавіт (EN/UA):",
    poly_in: "Вхідний текст:",
    poly_out: "Результат:",
    poly_enc: "Зашифрувати",
    poly_dec: "Розшифрувати",
    vig_title: "Шифр Віженера",
    vig_alpha: "Алфавіт:",
    vig_in: "Вхідний текст:",
    vig_key: "Ключ:",
    vig_rot: "ROT (зсув):",
    vig_enc: "ЗАШИФРУВАТИ",
    vig_dec: "РОЗШИФРУВАТИ",
    vig_tbl_gen: "Згенерувати таблицю",
    vig_tbl_copy: "Копіювати таблицю",
    vig_tbl_label: "Таблиця (оригінал | ключ | результат):",
    cip_title: "Cipser (Цезар)",
    cip_in: "Вхідний текст:",
    cip_alpha: "Алфавіт:",
    cip_shift: "Зсув (ціле):",
    cip_enc: "Зашифрувати",
    cip_dec: "Розшифрувати",
    about_title: "Про автора",
    about_text: `Автори: Крилевич Мирослав \nГрупа: УБД-32\nВерсія: ${APP_VERSION}`,
    about_links: "Посилання: GitHub/QmFkLVBp",
  },
  en: {
    title: "DECRYPTOINATOR LITE",
    nav: ["RSA", "Polybius", "Vigenère", "Cipser", "Settings", "About"],
    log_title: "Logs:",
    rsa_title: "RSA — Task 4",
    rsa_desc: "Known: d or e, p, q. Compute N, φ(N), e, Ek, Dk. Encrypt M, Decrypt C.",
    rsa_labels: { d: "d (private, optional):", e: "e (public, optional):", p: "p:", q: "q:", M: "M:", C: "C:" },
    rsa_actions: { compute: "Compute", enc: "Encrypt M → C", dec: "Decrypt C → M" },
    rsa_params: "Parameters (N, φ(N), e, Ek, Dk):",
    poly_title: "Polybius Square",
    poly_alpha: "Alphabet (EN/UA):",
    poly_in: "Input text:",
    poly_out: "Output:",
    poly_enc: "Encrypt",
    poly_dec: "Decrypt",
    vig_title: "Vigenère",
    vig_alpha: "Alphabet:",
    vig_in: "Input text:",
    vig_key: "Key:",
    vig_rot: "ROT (shift):",
    vig_enc: "ENCRYPT",
    vig_dec: "DECRYPT",
    vig_tbl_gen: "Generate table",
    vig_tbl_copy: "Copy table",
    vig_tbl_label: "Table (orig | key | result):",
    cip_title: "Cipser (Caesar)",
    cip_in: "Input text:",
    cip_alpha: "Alphabet:",
    cip_shift: "Shift (int):",
    cip_enc: "Encrypt",
    cip_dec: "Decrypt",
    about_title: "About",
    about_text: `Author: Krylevych Myroslav \nGroup: UBD-32\nVersion: ${APP_VERSION}`,
    about_links: "Links: GitHub/QmFkLVBp",
  }
};

const byId = (id) => document.getElementById(id);
const appendLog = (boxId, msg) => { const el = byId(boxId); el.value = (el.value ? el.value + "\n" : "") + msg; };
const setText = (id, text) => { byId(id).value = text; };
const getText = (id) => byId(id).value;

// Math (BigInt)
function egcd(a, b) { if (b === 0n) return [a, 1n, 0n]; const [g, x1, y1] = egcd(b, a % b); return [g, y1, x1 - (a / b) * y1]; }
function modinv(a, m) { const [g, x] = egcd(a, m); if (g !== 1n) throw new Error("No modular inverse (gcd != 1)"); return ((x % m) + m) % m; }
function modPow(base, exp, mod) { let result = 1n; let b = ((base % mod) + mod) % mod; let e = exp; while (e > 0n) { if (e & 1n) result = (result * b) % mod; b = (b * b) % mod; e >>= 1n; } return result; }

// Crypto helpers
function rotateAlphabet(alpha, rot) { if (!alpha) return alpha; rot = ((rot % alpha.length) + alpha.length) % alpha.length; return alpha.slice(rot) + alpha.slice(0, rot); }
function vigenere(text, key, encrypt, up) {
  if (!key) throw new Error("Key required");
  const keyUp = key.toUpperCase();
  for (const ch of keyUp) if (!up.includes(ch)) throw new Error("Key contains invalid characters");
  const out = []; let ki = 0; const n = up.length;
  for (const ch of text) {
    const cu = ch.toUpperCase();
    if (up.includes(cu)) {
      const tp = up.indexOf(cu), kp = up.indexOf(keyUp[ki % keyUp.length]);
      const rp = encrypt ? (tp + kp) % n : (tp - kp + n) % n;
      const rc = up[rp];
      out.push(ch === ch.toUpperCase() ? rc : rc.toLowerCase()); ki++;
    } else out.push(ch);
  }
  return out.join("");
}
function vigenereTable(text, key, up) {
  if (!key) throw new Error("Key required");
  const keyUp = key.toUpperCase();
  for (const ch of keyUp) if (!up.includes(ch)) throw new Error("Key contains invalid characters");
  const n = up.length; const ks = [], ct = [], shifts = []; let ki = 0;
  for (const ch of text) {
    const cu = ch.toUpperCase();
    if (up.includes(cu)) {
      const kch = keyUp[ki % keyUp.length], shift = up.indexOf(kch);
      const encPos = (up.indexOf(cu) + shift) % n, encCh = up[encPos];
      ks.push(ch === ch.toUpperCase() ? kch : kch.toLowerCase());
      ct.push(ch === ch.toUpperCase() ? encCh : encCh.toLowerCase());
      shifts.push(shift); ki++;
    } else { ks.push("-"); ct.push(ch); shifts.push(-1); }
  }
  const orig = text, kstream = ks.join(""), cipher = ct.join("");
  const header = `${"Idx".padStart(4)} ${"Orig".padStart(3).padEnd(6)} ${"Key".padStart(3).padEnd(6)} ${"Shift".padStart(5)} ${"Enc".padStart(3).padEnd(6)}`;
  const lines = [header, "-".repeat(header.length)];
  for (let i = 1, j = 0; j < orig.length; j++, i++) {
    const o = orig[j].replace?.("\t","\\t").replace?.("\n","\\n") ?? orig[j];
    const k = kstream[j], s = shifts[j] >= 0 ? String(shifts[j]) : "-", c = cipher[j].replace?.("\t","\\t").replace?.("\n","\\n") ?? cipher[j];
    lines.push(`${String(i).padStart(4)} ${o.padStart(3).padEnd(6)} ${k.padStart(3).padEnd(6)} ${s.padStart(5)} ${c.padStart(3).padEnd(6)}`);
  }
  return ["Original: " + orig, "Keystream: " + kstream, "Encrypted: " + cipher, "", ...lines].join("\n");
}
function caesar(text, shift, up, lo) {
  const n = up.length, s = ((shift % n) + n) % n; let out = "";
  for (const ch of text) {
    if (up.includes(ch)) out += up[(up.indexOf(ch) + s) % n];
    else if (lo.includes(ch)) out += lo[(lo.indexOf(ch) + s) % n];
    else out += ch;
  }
  return out;
}

// State
let currentLang = "ua";
let currentTheme = "Нічна Прохолода";
let rsaState = null;

// UI helpers
function showPage(key) { for (const sec of document.querySelectorAll(".page")) sec.hidden = true; byId(`page-${key}`).hidden = false; }
function applyTheme() { const cls = THEMES[currentTheme].class; if (cls === "theme-light") document.body.classList.add("theme-light"); else document.body.classList.remove("theme-light"); }
function onLangChange() {
  const L = LANG[currentLang];
  document.title = L.title;
  byId("page-title").textContent = L.title;
  // RSA
  byId("rsa-title").textContent = L.rsa_title;
  byId("rsa-desc").textContent = L.rsa_desc;
  byId("label-d").textContent = L.rsa_labels.d;
  byId("label-e").textContent = L.rsa_labels.e;
  byId("label-p").textContent = L.rsa_labels.p;
  byId("label-q").textContent = L.rsa_labels.q;
  byId("label-M").textContent = L.rsa_labels.M;
  byId("label-C").textContent = L.rsa_labels.C;
  byId("btn-rsa-compute").textContent = L.rsa_actions.compute;
  byId("btn-rsa-enc").textContent = L.rsa_actions.enc;
  byId("btn-rsa-dec").textContent = L.rsa_actions.dec;
  byId("rsa-params-header").textContent = L.rsa_params;
  byId("rsa-log-header").textContent = L.log_title;
  // Polybius
  byId("poly-title").textContent = L.poly_title;
  byId("poly-alpha-label").textContent = L.poly_alpha;
  byId("poly-in-label").textContent = L.poly_in;
  byId("poly-out-label").textContent = L.poly_out;
  byId("btn-poly-enc").textContent = L.poly_enc;
  byId("btn-poly-dec").textContent = L.poly_dec;
  byId("poly-log-header").textContent = L.log_title;
  // Vigenère
  byId("vig-title").textContent = L.vig_title;
  byId("vig-alpha-label").textContent = L.vig_alpha;
  byId("vig-in-label").textContent = L.vig_in;
  byId("vig-key-label").textContent = L.vig_key;
  byId("vig-rot-label").textContent = L.vig_rot;
  byId("btn-vig-enc").textContent = L.vig_enc;
  byId("btn-vig-dec").textContent = L.vig_dec;
  byId("btn-vig-tbl-gen").textContent = L.vig_tbl_gen;
  byId("btn-vig-tbl-copy").textContent = L.vig_tbl_copy;
  byId("vig-tbl-label").textContent = L.vig_tbl_label;
  byId("vig-log-header").textContent = L.log_title;
  // Cipser
  byId("cip-title").textContent = L.cip_title;
  byId("cip-in-label").textContent = L.cip_in;
  byId("cip-alpha-label").textContent = L.cip_alpha;
  byId("cip-shift-label").textContent = L.cip_shift;
  byId("btn-cip-enc").textContent = L.cip_enc;
  byId("btn-cip-dec").textContent = L.cip_dec;
  byId("cip-out-label").textContent = L.poly_out;
  byId("cip-log-header").textContent = L.log_title;
  // Settings/About
  byId("settings-title").textContent = L.nav[4];
  byId("settings-log-header").textContent = L.log_title;
  byId("about-title").textContent = L.about_title;
  byId("about-text").textContent = L.about_text;
  byId("about-links").textContent = L.about_links;
  byId("about-log-header").textContent = L.log_title;
}

// Logo load
async function loadLogo(holderId) {
  const holder = byId(holderId);
  const url = "https://raw.githubusercontent.com/QmFkLVBp/decryptoinator/main/assets/logo.png";
  try {
    const res = await fetch(url);
    if (res.ok) {
      const img = document.createElement("img");
      img.src = url; img.alt = "DECRYPTOINATOR"; img.style.maxWidth = "220px";
      holder.appendChild(img);
    } else {
      const h = document.createElement("h3"); h.textContent = "DECRYPTOINATOR"; holder.appendChild(h);
    }
  } catch {
    const h = document.createElement("h3"); h.textContent = "DECRYPTOINATOR"; holder.appendChild(h);
  }
}

// RSA
function intval(s) { s = String(s).trim(); return s && /^-?\d+$/.test(s) ? BigInt(s) : null; }
function requireInt(s, name) { s = String(s).trim(); if (!s || !/^-?\d+$/.test(s)) throw new Error(`${name} must be integer`); return BigInt(s); }
function rsaCompute() {
  try {
    const p = requireInt(byId("rsa-p").value, "p");
    const q = requireInt(byId("rsa-q").value, "q");
    if (p <= 1n || q <= 1n) throw new Error("p,q must be > 1");
    const N = p * q, phi = (p - 1n) * (q - 1n);
    let d = intval(byId("rsa-d").value), e = intval(byId("rsa-e").value);
    if (d === null && e === null) throw new Error("Provide at least d or e");
    if (d !== null && e === null) e = modinv(d % phi, phi);
    else if (e !== null && d === null) d = modinv(e % phi, phi);
    else if ((e * d) % phi !== 1n) throw new Error("e and d are not modular inverses modulo φ(N)");
    rsaState = { p, q, N, phi, d, e };
    const text = [`d = ${d}`, `e = ${e}`, `p = ${p}`, `q = ${q}`, `N = ${N}`, `φ(N) = ${phi}`, `Ek = (${e}, ${N})`, `Dk = (${d}, ${N})`].join("\n");
    setText("rsa-params", text);
    appendLog("rsa-log", "Computed RSA parameters");
  } catch (exc) {
    rsaState = null;
    appendLog("rsa-log", `Compute error: ${exc.message ?? exc}`);
    alert(`RSA compute: ${exc.message ?? exc}`);
  }
}
function rsaEncrypt() {
  try {
    if (!rsaState) { appendLog("rsa-log", "Auto compute..."); rsaCompute(); }
    if (!rsaState) throw new Error("RSA params not available");
    const { N, e } = rsaState;
    const M = requireInt(byId("rsa-M").value, "M");
    if (!(0n <= M && M < N)) throw new Error(`M must be in [0, ${N - 1n}]`);
    const C = modPow(M, e, N);
    const prev = byId("rsa-params").value.trim();
    setText("rsa-params", prev + `\n\nEncrypt:\nM = ${M}\nC = ${C}\n`);
    appendLog("rsa-log", `Encryption done. C=${C}`);
  } catch (exc) {
    appendLog("rsa-log", `Encrypt error: ${exc.message ?? exc}`);
    alert(`RSA encrypt: ${exc.message ?? exc}`);
  }
}
function rsaDecrypt() {
  try {
    if (!rsaState) { appendLog("rsa-log", "Auto compute..."); rsaCompute(); }
    if (!rsaState) throw new Error("RSA params not available");
    const { N, d } = rsaState;
    const C = requireInt(byId("rsa-C").value, "C");
    if (!(0n <= C && C < N)) throw new Error(`C must be in [0, ${N - 1n}]`);
    const M = modPow(C, d, N);
    const prev = byId("rsa-params").value.trim();
    setText("rsa-params", prev + `\n\nDecrypt:\nC = ${C}\nM = ${M}\n`);
    appendLog("rsa-log", `Decryption done. M=${M}`);
  } catch (exc) {
    appendLog("rsa-log", `Decrypt error: ${exc.message ?? exc}`);
    alert(`RSA decrypt: ${exc.message ?? exc}`);
  }
}

// Polybius
function polyAlpha(kind) { return kind === "EN" ? "ABCDEFGHIKLMNOPQRSTUVWXYZ" : UA_UP + "012"; }
function polyMaps(alphabet) {
  const s = [...new Set(alphabet)].join(""), size = (s.length === 25) ? 5 : 6;
  const enc = {}, dec = {}; let idx = 0;
  for (let r = 1; r <= size; r++) for (let c = 1; c <= size; c++) {
    const ch = s[idx++]; enc[ch] = `${r}${c}`; dec[`${r}${c}`] = ch;
  }
  return [enc, dec];
}
function polyRun(encrypt) {
  try {
    const alpha = polyAlpha(byId("poly-alpha").value);
    const text = getText("poly-in");
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
      res = tokens.map(t => dec[t] ?? t).join("");
    }
    setText("poly-out", res);
    appendLog("poly-log", "Done Polybius.");
  } catch (e) {
    appendLog("poly-log", `Polybius error: ${e.message ?? e}`);
    alert(`Polybius: ${e.message ?? e}`);
  }
}

// Vigenère
function vigAlph() { return (byId("vig-alpha").value === "UA") ? [UA_UP, UA_LO] : [EN_UP, EN_LO]; }
function vigRotVal(up) {
  const s = byId("vig-rot").value.trim();
  if (/^-?\d+$/.test(s)) {
    const val = parseInt(s, 10);
    // invert sign to match desktop comment
    return ((-val % up.length) + up.length) % up.length;
  }
  return 0;
}
function vigRun(encrypt) {
  try {
    const [up] = vigAlph();
    const rot = vigRotVal(up);
    const upR = rotateAlphabet(up, rot);
    const text = getText("vig-in");
    const key = byId("vig-key").value.trim();
    const res = vigenere(text, key, encrypt, upR);
    setText("vig-out", res);
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
    const text = getText("vig-in");
    const key = byId("vig-key").value.trim();
    const tbl = vigenereTable(text, key, upR);
    setText("vig-tbl", `Alphabet (ROT=${rot}): ${upR}\n${tbl}`);
    appendLog("vig-log", "Mapping table generated");
  } catch (e) {
    appendLog("vig-log", `Table error: ${e.message ?? e}`);
    alert(`Vigenère table: ${e.message ?? e}`);
  }
}
function vigCopyTable() {
  try {
    const content = getText("vig-tbl");
    navigator.clipboard.writeText(content);
    appendLog("vig-log", "Table copied to clipboard");
  } catch (e) {
    appendLog("vig-log", `Copy error: ${e.message ?? e}`);
    alert(`Copy: ${e.message ?? e}`);
  }
}

// Cipser
function cipRun(encrypt) {
  try {
    const up = (byId("cip-alpha").value === "UA") ? UA_UP : EN_UP;
    const lo = (byId("cip-alpha").value === "UA") ? UA_LO : EN_LO;
    const s = byId("cip-shift").value.trim();
    const shift = /^-?\d+$/.test(s) ? parseInt(s, 10) : 0;
    const text = getText("cip-in");
    const res = caesar(text, (encrypt ? shift : -shift), up, lo);
    setText("cip-out", res);
    appendLog("cip-log", "Cipser done");
  } catch (e) {
    appendLog("cip-log", `Cipser error: ${e.message ?? e}`);
    alert(`Cipser: ${e.message ?? e}`);
  }
}

// Navigation
function setupNav() {
  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.addEventListener("click", () => showPage(btn.dataset.page));
  });
  showPage("rsa");
}

// Settings
function setupSettings() {
  byId("select-lang").value = currentLang;
  byId("select-theme").value = currentTheme;
  byId("select-lang").addEventListener("change", (e) => {
    currentLang = e.target.value; onLangChange();
  });
  byId("select-theme").addEventListener("change", (e) => {
    currentTheme = e.target.value; applyTheme();
  });
}

// Init
window.addEventListener("DOMContentLoaded", () => {
  setupNav();
  setupSettings();
  onLangChange();
  applyTheme();

  loadLogo("logo-holder");
  loadLogo("about-logo-holder");

  appendLog("rsa-log", "Ready: RSA");
  appendLog("poly-log", "Ready: Polybius");
  appendLog("vig-log", "Ready: Vigenère");
  appendLog("cip-log", "Ready: Cipser");
  appendLog("settings-log", "Ready: Settings");
  appendLog("about-log", "Ready: About");
});
