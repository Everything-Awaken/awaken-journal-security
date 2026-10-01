//Part-A

import { argon2id } from "../vendor/hash-wasm.js";

// A cryptographically secure random byte generator — built into every browser.
// This is what makes salts and keys genuinely unpredictable, not just "random-ish".
function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

// Salts travel to/from the server as base64. Argon2id must see the SAME raw bytes
// on login as on signup, so decode back to bytes — never hash the base64 string.
function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
// Chunked bytes→base64 (avoids String.fromCharCode(...spread) arg limits on larger blobs).
function bytesToB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

//Part-B

async function deriveKeys(password, authSalt, encSalt) {
  // Derivation #1: proves identity to the server. This value gets SENT.
  const authHash = await argon2id({
    password,
    salt: authSalt,
    parallelism: 1,
    iterations: 2,
    memorySize: 19456,   // 19 MiB, in KB — matches our locked protocol spec
    hashLength: 32,
    outputType: "encoded", // a self-describing string, easy to store & verify later
  });

  // Derivation #2: unlocks data. This value NEVER leaves the browser.
  const encKeyBytes = await argon2id({
    password,
    salt: encSalt,        // a DIFFERENT salt — this is what makes the two outputs unrelated
    parallelism: 1,
    iterations: 2,
    memorySize: 19456,
    hashLength: 32,
    outputType: "binary",  // raw bytes, because we feed this straight into AES next
  });

  return { authHash, encKeyBytes };
}

// Derive ONLY the encryption key (unlock path — no identity proof needed).
async function deriveEncKey(password, encSaltBytes) {
  return argon2id({
    password, salt: encSaltBytes, parallelism: 1, iterations: 2,
    memorySize: 19456, hashLength: 32, outputType: "binary",
  });
}

//Part-C

async function encryptMasterKey(encKeyBytes) {
  // Import the derived bytes as an actual usable AES key
  const encKey = await crypto.subtle.importKey(
    "raw", encKeyBytes, "AES-GCM", false, ["encrypt"]
  );

  // The REAL key that will eventually encrypt journal entries — random, not password-derived
  const masterKey = randomBytes(32);

  // AES-GCM needs a fresh, unique IV (like a "starting position") for every encryption
  const iv = randomBytes(12);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, encKey, masterKey
  );

  // We store iv + ciphertext together (iv isn't secret — we just need it later to decrypt)
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return btoa(String.fromCharCode(...combined)); // base64 string, ready to send to server
}

// Reverse of encryptMasterKey: unseal the random master key with the password-derived encKey.
async function decryptMasterKey(encKeyBytes, encMKb64) {
  const data = b64ToBytes(encMKb64);
  const key = await crypto.subtle.importKey("raw", encKeyBytes, "AES-GCM", false, ["decrypt"]);
  const mk = await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.subarray(0, 12) }, key, data.subarray(12));
  return new Uint8Array(mk); // 32 raw bytes
}

// ---- content E2EE: encrypt/decrypt journal payloads with the master key ----
// importKey is costly and the master key never changes within a session — import ONCE and
// reuse the CryptoKey for every encrypt/decrypt (hundreds per page). Cache keys off the
// bytes' b64 form (32 bytes — cheap) so a relock/account switch naturally invalidates it.
let keyCache = { b64: null, key: null };
async function aesKeyFor(masterKeyBytes) {
  const b64 = bytesToB64(masterKeyBytes);
  if (keyCache.b64 !== b64) {
    keyCache = { b64, key: await crypto.subtle.importKey("raw", masterKeyBytes, "AES-GCM", false, ["encrypt", "decrypt"]) };
  }
  return keyCache.key;
}
export async function encryptText(masterKeyBytes, str) {
  const key = await aesKeyFor(masterKeyBytes);
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(str));
  const combined = new Uint8Array(iv.length + ct.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ct), iv.length);
  return bytesToB64(combined);
}
export async function decryptText(masterKeyBytes, b64) {
  const data = b64ToBytes(b64);
  const key = await aesKeyFor(masterKeyBytes);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.subarray(0, 12) }, key, data.subarray(12));
  return new TextDecoder().decode(pt);
}

// Master key lives ONLY in the browser (sessionStorage, cleared on tab close). Never sent.
const MK_KEY = "aj.mk";
export function setMasterKey(bytes) { try { sessionStorage.setItem(MK_KEY, bytesToB64(bytes)); } catch (e) {} }
export function getMasterKey() { try { const b = sessionStorage.getItem(MK_KEY); return b ? b64ToBytes(b) : null; } catch (e) { return null; } }
export function clearMasterKey() { keyCache = { b64: null, key: null }; try { sessionStorage.removeItem(MK_KEY); } catch (e) {} }

//Part-D

// Create an account (invite-gated). Returns the fetch Response so the caller can
// surface 201 / 403 (bad invite) / 409 (name taken) in the UI.
export async function signup(username, email, password, inviteToken) {
  const authSalt = randomBytes(16);
  const encSalt = randomBytes(16);

  const { authHash, encKeyBytes } = await deriveKeys(password, authSalt, encSalt);
  const encryptedMasterKey = await encryptMasterKey(encKeyBytes);

  // Only THESE go to the server — never the password, never encKeyBytes, never masterKey.
  return fetch("/api/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      inviteToken,
      username,
      email,
      authHash,
      authSalt: btoa(String.fromCharCode(...authSalt)),
      encSalt: btoa(String.fromCharCode(...encSalt)),
      encryptedMasterKey,
    }),
  });
}

// Log in with a username OR email. Fetch salts, derive BOTH keys (authHash proves
// identity; encKey unseals the master key), verify, then stash the master key in the
// browser. Returns the verify Response (200 sets the session cookie).
export async function login(identifier, password) {
  const saltRes = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier }),
  });
  if (!saltRes.ok) return saltRes;
  const { authSalt, encSalt } = await saltRes.json();

  const { authHash, encKeyBytes } = await deriveKeys(password, b64ToBytes(authSalt), b64ToBytes(encSalt));

  const res = await fetch("/api/login/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // so the __Host-session cookie is set/sent
    body: JSON.stringify({ identifier, authHash }),
  });
  if (res.ok) {
    try {
      const { encryptedMasterKey } = await res.clone().json();
      setMasterKey(await decryptMasterKey(encKeyBytes, encryptedMasterKey));
    } catch (e) { /* leave key unset → /app will prompt unlock */ }
  }
  return res;
}

// Re-unlock on a reload/new tab: valid session cookie but no key in sessionStorage.
// Only the password can rebuild the encKey → unseal the master key. Returns true on success.
export async function unlock(password) {
  const meRes = await fetch("/api/me", { credentials: "include" });
  if (!meRes.ok) return false;
  const { encSalt, encryptedMasterKey } = await meRes.json();
  if (!encSalt || !encryptedMasterKey) return false;
  try {
    const encKeyBytes = await deriveEncKey(password, b64ToBytes(encSalt));
    setMasterKey(await decryptMasterKey(encKeyBytes, encryptedMasterKey));
    return true;
  } catch (e) { return false; } // wrong password → GCM auth fails
}


//Part-D2 — Backup & Restore (v0.6.9). Seals/unseals a whole-vault JSON blob with a key
// derived from the ACCOUNT PASSWORD (not the master key) on a fresh random salt — same
// deriveEncKey()/AES-GCM recipe as unlocking, just a new salt per file so two backups
// never share a key. Wrong password fails the same way unlock() does: GCM auth throws.
export async function sealBackup(password, plaintext) {
  const salt = randomBytes(16);
  const keyBytes = await deriveEncKey(password, salt);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return { version: 1, salt: bytesToB64(salt), iv: bytesToB64(iv), ciphertext: bytesToB64(new Uint8Array(ct)) };
}
export async function unsealBackup(password, file) {
  if (file?.version !== 1) throw new Error("Incompatible backup file.");
  const keyBytes = await deriveEncKey(password, b64ToBytes(file.salt));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(file.iv) }, key, b64ToBytes(file.ciphertext));
  return new TextDecoder().decode(pt);
}

//Part-E — Google/Apple sign-in (identity-only). The provider proved WHO the user is via
// the pending cookie the server holds; this seals a fresh master key with a VAULT
// PASSPHRASE exactly the way signup() does with the password — deriveEncKey() and
// encryptMasterKey() reused unmodified, no authHash/authSalt at all. Returns the Response;
// 201 means the server also created the session (auto-login).
export async function oauthSignup(username, passphrase) {
  const encSalt = randomBytes(16);
  const encKeyBytes = await deriveEncKey(passphrase, encSalt);
  const encryptedMasterKey = await encryptMasterKey(encKeyBytes);
  const res = await fetch("/api/oauth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ username, encSalt: bytesToB64(encSalt), encryptedMasterKey }),
  });
  if (res.status === 201) {
    try { setMasterKey(await decryptMasterKey(encKeyBytes, encryptedMasterKey)); } catch (e) { /* /app will prompt unlock */ }
  }
  return res;
}
