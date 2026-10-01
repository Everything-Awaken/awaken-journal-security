# Awaken Journal — Security & Privacy

**Awaken Journal by Everything Awaken is a private, end-to-end encrypted journal app** — journal, to-do, notes and personal finance on one day page. Everything you write is encrypted on your own device before it reaches our server. We cannot read it.

This repository is where you can check that claim instead of trusting it.

| | |
|---|---|
| [`STANDARD.md`](STANDARD.md) | The Awaken Journal Standard: our Privacy Protocol and all 47 controls of our Security Protocol, in plain words with the technical detail. Mirror of [everythingawaken.com/journal/standard/](https://everythingawaken.com/journal/standard/). |
| [`crypto/`](crypto/) | The exact browser-side encryption code Awaken Journal runs, test vectors, and an **independent** checker that re-derives every vector with different libraries. |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability. |

## Verify it yourself

```sh
cd crypto
pip install argon2-cffi cryptography
python verify-vectors.py vectors.json
# → 59 checks passed, 0 failed
```

The vectors were produced by running our own `crypto.js` unmodified. The checker shares no code with it: Argon2id comes from the reference C implementation, AES-GCM from OpenSSL. If the two agree byte for byte, the code does what the Standard says. Our Android and iPhone apps are tested against the same vectors.

## What this repository is not

It is not the whole app. The server and app code are private for now; this repository holds what you need to check the promise: the rules, the encryption, and proof that they match. Nothing here is a secret — the encryption code is already delivered to every browser that opens Awaken Journal, and security never depends on hiding it.

## Links

- Awaken Journal: [everythingawaken.com/journal](https://everythingawaken.com/journal)
- Privacy Policy: [everythingawaken.com/journal/privacy](https://everythingawaken.com/journal/privacy)
- Everything Awaken: [everythingawaken.com](https://everythingawaken.com)

## Licence

Code (`crypto/`) is licensed under the [Apache License 2.0](LICENSE). Documents (`STANDARD.md`, the READMEs, `SECURITY.md`) are licensed under [Creative Commons Attribution 4.0](LICENSE-DOCS) — quote and share them with credit to Everything Awaken.

© 2026 Everything Awaken™ (Tanureet Kaur Randhawa, Punjab, India).
