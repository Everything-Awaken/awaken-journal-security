# INDEPENDENT re-derivation of vectors.json. Shares no code with crypto.js:
# Argon2id = argon2-cffi (the reference C implementation), AES-GCM = `cryptography` (OpenSSL).
# Every sealed value is recomputed from the stated inputs and compared byte-for-byte.
# Also writes intermediates.json: the encKey bytes a native app must derive (crypto.js never
# exposes them, so they can only come from here — and they're cross-checked by unsealing).
#
# Run:  python verify-vectors.py vectors.json   (pip install argon2-cffi cryptography)
import base64, json, sys
from argon2.low_level import hash_secret, hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

v = json.load(open(sys.argv[1]))
P = v["params"]
ok, bad = 0, []
def check(name, cond):
    global ok
    if cond: ok += 1
    else: bad.append(name)

H = bytes.fromhex
def kdf_raw(pw, salt): return hash_secret_raw(pw, salt, time_cost=P["iterations"], memory_cost=P["memoryKiB"], parallelism=P["parallelism"], hash_len=P["hashLength"], type=Type.ID)
def kdf_enc(pw, salt): return hash_secret(pw, salt, time_cost=P["iterations"], memory_cost=P["memoryKiB"], parallelism=P["parallelism"], hash_len=P["hashLength"], type=Type.ID).decode()
def seal(key, iv, pt): return base64.b64encode(iv + AESGCM(key).encrypt(iv, pt, None)).decode()

inter = {"account": [], "backup": [], "oauth": []}

for a in v["account"]:
    pw = H(a["passwordUtf8Hex"])
    check(a["id"] + " utf8", pw == a["password"].encode("utf-8"))
    b = a["signupBody"]
    check(a["id"] + " authSalt b64", base64.b64decode(b["authSalt"]) == H(a["authSaltHex"]))
    check(a["id"] + " encSalt b64", base64.b64decode(b["encSalt"]) == H(a["encSaltHex"]))
    check(a["id"] + " authHash (PHC string)", kdf_enc(pw, H(a["authSaltHex"])) == b["authHash"])
    enc_key = kdf_raw(pw, H(a["encSaltHex"]))
    check(a["id"] + " encryptedMasterKey", seal(enc_key, H(a["masterKeyIvHex"]), H(a["masterKeyHex"])) == b["encryptedMasterKey"])
    check(a["id"] + " login unseal", a["loginAuthHashMatchesSignup"] and a["loginUnsealedMasterKeyHex"] == a["masterKeyHex"])
    inter["account"].append({"id": a["id"], "encKeyHex": enc_key.hex()})

nfc = next(a for a in v["account"] if a["id"] == "A3-cafe-nfc"); nfd = next(a for a in v["account"] if a["id"] == "A4-cafe-nfd")
check("A3/A4 same salts", nfc["authSaltHex"] == nfd["authSaltHex"] and nfc["encSaltHex"] == nfd["encSaltHex"])
check("A3/A4 NO normalisation (outputs differ)", nfc["signupBody"]["authHash"] != nfd["signupBody"]["authHash"])

for c in v["content"]:
    check(c["id"] + " utf8", H(c["plaintextUtf8Hex"]) == c["plaintext"].encode("utf-8"))
    check(c["id"] + " sealed", seal(H(c["masterKeyHex"]), H(c["ivHex"]), c["plaintext"].encode("utf-8")) == c["sealed"])
    check(c["id"] + " length = 12 + n + 16", len(base64.b64decode(c["sealed"])) == 12 + len(c["plaintext"].encode("utf-8")) + 16)

for bk in v["backup"]:
    key = kdf_raw(bk["password"].encode("utf-8"), H(bk["saltHex"])); f = bk["file"]
    check(bk["id"] + " file.salt/iv", base64.b64decode(f["salt"]) == H(bk["saltHex"]) and base64.b64decode(f["iv"]) == H(bk["ivHex"]))
    check(bk["id"] + " file.ciphertext (no iv prefix)", base64.b64encode(AESGCM(key).encrypt(H(bk["ivHex"]), bk["plaintext"].encode(), None)).decode() == f["ciphertext"])
    inter["backup"].append({"id": bk["id"], "keyHex": key.hex()})

for o in v["oauth"]:
    key = kdf_raw(o["passphrase"].encode("utf-8"), H(o["encSaltHex"]))
    check(o["id"] + " body.encSalt", base64.b64decode(o["body"]["encSalt"]) == H(o["encSaltHex"]))
    check(o["id"] + " body.encryptedMasterKey", seal(key, H(o["masterKeyIvHex"]), H(o["masterKeyHex"])) == o["body"]["encryptedMasterKey"])
    check(o["id"] + " no authHash sent", "authHash" not in o["body"])
    inter["oauth"].append({"id": o["id"], "encKeyHex": key.hex()})

mk = H(v["content"][0]["masterKeyHex"])
for n in v["negative"]:
    check(n["id"] + " failed in crypto.js", n["mustFail"])
    if "sealed" in n:
        raw = base64.b64decode(n["sealed"]); key = H(n["wrongKeyHex"]) if "wrongKeyHex" in n else mk
        try: AESGCM(key).decrypt(raw[:12], raw[12:], None); check(n["id"] + " fails independently", False)
        except InvalidTag: check(n["id"] + " fails independently", True)

json.dump(inter, open("intermediates.json", "w"), indent=2)
print(f"{ok} checks passed, {len(bad)} failed")
for b in bad: print("  FAIL:", b)
sys.exit(1 if bad else 0)
