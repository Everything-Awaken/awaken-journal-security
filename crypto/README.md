# Awaken Journal encryption — code, test vectors, independent check

| File | What it is |
|---|---|
| `crypto.js` | The browser-side encryption code Awaken Journal runs, unmodified. It imports [`hash-wasm`](https://github.com/Daninet/hash-wasm) (MIT) for Argon2id; that library isn't copied here. |
| `vectors.json` | Fixed inputs → exact expected outputs, produced by running `crypto.js` itself. All passwords, keys and users are made up. |
| `verify-vectors.py` | An independent re-derivation of every vector. Shares no code with `crypto.js`: Argon2id via [argon2-cffi](https://github.com/hynek/argon2-cffi) (the reference C code), AES-GCM via [cryptography](https://cryptography.io) (OpenSSL). |
| `intermediates.json` | The password-derived encryption-key bytes for each vector (`crypto.js` never exposes them). Written by the checker and proven correct by unsealing. |

```sh
pip install argon2-cffi cryptography
python verify-vectors.py vectors.json   # → 59 checks passed, 0 failed
```

## The contract

| | Rule |
|---|---|
| Key derivation | Argon2id v19, **memory 19456 KiB, 2 iterations, parallelism 1, 32-byte output** |
| Password bytes | UTF-8, **no Unicode normalisation** (vectors include "café" as NFC and NFD — they give different keys) |
| Two salts | `authSalt` → a login proof sent to the server · `encSalt` → the encryption key, which never leaves the device |
| Login proof | The Argon2id PHC string `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`. The server stores it only after mixing in a server-side secret (pepper). |
| Master key | 32 random bytes, sealed with the password-derived key. Your content is encrypted with the master key, so changing your password re-seals one small key. |
| Sealed format | `base64( iv[12] ‖ ciphertext ‖ tag[16] )`, AES-256-GCM, no AAD, a fresh random IV every time |
| Content | text → UTF-8 → seal. Ciphertext length = 12 + plaintext length + 16, so the length of an entry is visible (we say so in the Standard). |
| Backup file | `{version:1, salt, iv, ciphertext}` — key = Argon2id(password, fresh salt) |
| Google/Apple sign-in | Same, but no login proof: the key comes from a separate vault passphrase |

These parameters are a permanent contract: every Awaken Journal client — web, Android, iPhone — must reproduce these vectors byte for byte.
