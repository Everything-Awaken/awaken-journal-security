# The Awaken Journal Standard

*Privacy Protocol v1.1 · Security Protocol v1.2 · Last verified against our running code: 1 October 2026*

**A journal is the most private thing a person owns.** Most of us hesitate to show our diary even to someone close. So before you write the true thing, you deserve to know exactly who could ever read it. This page is that answer, in full: the rules Awaken Journal is built to, in plain words first, with the technical detail one tap below for anyone who wants to check.

> Mirror of [everythingawaken.com/journal/standard/](https://everythingawaken.com/journal/standard/). The website is the source; this file is regenerated from it, never edited by hand.

**On this page:** [Part 1 · The Privacy Protocol](#part-1--the-privacy-protocol) — what we protect, from whom, and what we can and can't see. [Part 2 · The Security Protocol](#part-2--the-security-protocol) — the 47 controls that keep that promise true in practice. [Change log](#change-log).

## Part 1 · The Privacy Protocol

### Can the people who run a journal app read my entries?

In most apps, yes — they hold the key, so they *could*, even if they promise not to. Awaken is built so that we can't. We defend your writing from three parties, and none of them counts as a lesser threat: **from us** (the people who own the server), **from attackers**, and **from any AI**.

Our own test is blunt: if the person who owns Awaken's server can read one of your entries, we have failed. That's why the protection is in the design, not in a policy we could quietly change.

**Technical detail — the threat model**

Adversary 1 is the server owner, with root access to the host, a full database dump and every backup. Adversary 2 is an outside attacker: stolen database, stolen backup, compromised host, intercepted traffic. Adversary 3 is any AI model, ours or a vendor's. A design that stops attackers but not the server owner is rejected — encryption at rest alone isn't enough. The promise we can make: **a full server compromise yields ciphertext, not your writing.**

### What is an end-to-end encrypted journal?

It means your writing is locked on your own device before it travels anywhere, and only you hold the key. When you log in, your password produces two separate things: a **proof** that tells our server it's you, and a **key** that stays on your device and unlocks your writing. The proof can't be turned back into the key.

On a normal day that means: if someone stole our server tonight, they would get the shape of a database and pages of meaningless noise where your words should be.

**Technical detail — the cryptography**

- **Argon2id** derives both values from your password (19 MiB memory, 2 iterations, parallelism 1 — the OWASP baseline), in your browser.
- **Two independent salts:** one derives the login proof sent to us; the other derives the encryption key, which is never transmitted. Nothing we store lets us derive the key.
- A **pepper** — a server secret kept outside the database — is mixed into the stored login proof, so a stolen database alone can't be attacked offline.
- **AES-GCM** (your browser's built-in `crypto.subtle`) encrypts content and detects tampering. Every encryption uses a fresh random 12-byte IV.
- **Master-key indirection:** your content is encrypted with a random master key; that key is locked by your password-derived key. Changing your password re-locks one small key instead of re-encrypting everything.
- On the web, the unlocked master key is held only in your browser tab's session storage and cleared when the tab closes.

### What can Awaken see about me?

Less than almost any app you use, but not nothing — and we'd rather list it than let "we can't read your journal" sound like "we know nothing about you." We can see what's needed to run your account: your email, your username, when you last used the app, and the *shape* of your data — never its words.

**Technical detail — the complete list, checked against our database**

**Visible to us in plain text:** email, username · a one-way login proof and salts (never your password) · row IDs and timestamps · your Google/Apple sign-in ID, if you use one · when you last used the app · icon and colour choices · a push-notification address, only if you opt in · which reminders are on and at what time · the shape of your data (a task is a Frog and is done; a transaction is an expense in a given encrypted category; which journal section a line belongs to) · app settings (day cutoff hour, currency symbol, toolbar order, theme) · feedback messages you send us · a waitlist email, if you joined it · crash and usage telemetry (below).

**Only ever ciphertext to us:** journal entries · to-do titles and notes · money amounts, notes and category names · your own section, folder and review names · note titles and content.

Money totals and every score are computed on your device. We never receive a score or a total — only the ciphertext they're computed from.

### Do you use analytics or trackers?

No third-party analytics, trackers or advertising — none, anywhere in the app or on this site. We do keep the bare minimum to know the app works: crash reports (no content in them) and which module you opened and what action you took, with a timestamp. That second record is tied to your account, and we'd rather say so plainly than call it "anonymous."

**Technical detail — the two tiers**

**Tier 1, always on, disclosed:** crash/error reports (app version, module, device category, error message, stack trace — no request bodies, nothing decrypted) and per-account usage rows (account ID, module, action, timestamp), stored on our own server. **Tier 2, opt-in, off by default:** anything beyond that — patterns, scores, product analytics. Nothing exists in Tier 2 today. No session replay, ever. No device fingerprinting. The app never saves your IP address; rate limiting holds it in memory for at most an hour. Cloudflare, our network provider, carries all traffic (already encrypted end to end for your writing) under its own terms.

### Does AI read my journal?

No — not ours, not anyone's. Our server only holds ciphertext, so there is nothing for a server-side AI to read. If Awaken ever offers AI features, they run on your own device, on writing your device has already unlocked. If a device can't run them, it simply doesn't get them. A feature isn't worth breaking the one promise that matters.

### How do Awaken Notes work with Obsidian and my own AI tools?

Awaken Notes work like a markdown vault. In **Awaken Cloud** your notes are encrypted with your key and synced across your devices. If you choose, Awaken also keeps them as plain `.md` files in a folder on your own device, so Obsidian, any editor, or your own AI tools can read and edit them — and edits made there flow back into Awaken, encrypted.

Those folder files are not encrypted; that's what makes them readable. They're protected by your device, or by whatever service you sync that folder with — so pick that folder the way you'd pick where to keep a paper diary.

**Technical detail — and an honest correction**

Today the folder works in Chrome and Edge on a computer (File System Access API); sync runs on login, logout or on demand, and imports external edits and new files back into the encrypted store. Until 1 October 2026 an "Awaken Server" option also kept a plain copy of those files on our server — which meant we could have read them. We found it in our own review and removed it the same day: the server routes were deleted, the one affected folder was erased, and devices on the old setting moved to Awaken Cloud automatically.

### What happens in the Android and iPhone apps?

Our native apps are being built now and aren't released yet. The design they're built to: after you log in, the unlocked key stays on that phone, sealed inside the phone's own secure hardware. By default the app opens straight in, which means **your phone's screen lock is your journal's lock**. If you want more, turn on **Lock app** and Awaken asks for your fingerprint, face or PIN every time. The key never leaves the phone and is never backed up to any cloud. We'll re-verify this section against the real apps before they ship.

### What if I forget my password?

Then your writing can't be recovered — by you or by us. There's no reset into readable data, because a company that can do that could read your diary all along. This is the cost of the promise, stated once and plainly. The remedy is simple: **use a password manager**, and export a backup from Settings now and then. If you signed in with Google or Apple, the same applies to your vault passphrase.

### What happens when I delete my account?

It's deleted immediately — not flagged, not scheduled. Your journal, tasks, money, notes, reviews, sessions, usage history, feedback messages and waitlist email all go at once. Our nightly encrypted backups keep only the last three nights, so your account is gone from every backup within three nights.

**Technical detail — the one exception**

Anonymised crash reports survive with the link to your account removed — no identity, no content — so a bug bad enough to make someone leave is still visible to us. Plain note files in a folder on your own device are yours; deleting your account can't reach them.

### Is there a minimum age?

Yes: 14. If you're 14–17, please use Awaken with a parent's or guardian's permission. India's data protection law (DPDP) will require *verifiable* parental consent for under-18s once its rules apply in full on 13 May 2027; before then we'll either verify a parent's consent for 14–17-year-olds or raise the minimum age to 18.

### What would happen if Awaken were breached?

Your writing would stay unreadable — a compromise yields ciphertext. The plain account data above (email, username and so on) could be exposed, and that's what our incident plan is for: detect it, contain it by rotating whatever was affected, work out exactly which fields and how many accounts, tell you plainly what was and wasn't exposed, and log it. The plan is written; we haven't yet rehearsed it end to end, and the exact legal notification timeline under DPDP is still being mapped. We'll update this line when both are done.

## Part 2 · The Security Protocol

Encryption can be perfect and an app still lose to a missing rate limit or an unpatched library. These are the **47 controls** that keep the promise above true in practice, grouped in nine areas, checked against [OWASP's Application Security Verification Standard (ASVS 5.0)](https://owasp.org/www-project-application-security-verification-standard/) and verified item by item against our running code. Status on 1 October 2026: **47 of 47**. To be plain about what that is: it's our own internal review. No outside firm has audited Awaken yet; when one has, this page will say who and when.

### How is my login protected?

Your password is never sent or stored. What we keep can't be reversed, can't be cracked quickly even if stolen, and can't be used to tell whether an account exists.

**Technical detail — authentication (controls 1–8)**

- Every credential ever exposed during development has been rotated.
- Argon2id with OWASP baseline parameters; two independent salts; a pepper held outside the database.
- Unknown accounts get convincing fake salts, so login and signup can't reveal who has an account.
- Login proofs are compared in constant time against a same-length dummy when no account exists — no timing leak.
- Rate limits on every login and signup route, plus a per-account lockout after repeated failures that replies exactly like a wrong password.

### How are sessions protected?

Once you're in, your login lives in a cookie that page scripts can't read, other sites can't use, and that expires on its own.

**Technical detail — sessions (controls 9–14)**

- Cookie flags: `httpOnly` · `secure` · `sameSite=Strict` · `__Host-` prefix.
- A fresh random session ID on every login, including Google/Apple sign-in — same code path, no weaker route.
- Every session has an expiry. On the web, logging in ends every other session for that account, so a lost device is signed out the moment you log in elsewhere.
- Admin sessions are separate, expire, and are all revoked on an admin password change.

### How is the encryption implemented?

With the browser's own audited cryptography, not homemade code — and checked so that a failure can never leak a key into a log.

**Technical detail — cryptography (controls 15–20)**

- AES-GCM via `crypto.subtle`; master-key indirection; the database holds ciphertext only for everything you write.
- A fresh random IV at every encryption site; none reused or hard-coded.
- Your exported backup file uses the same key derivation and cipher as login, with its own fresh salt — not a weaker side scheme.
- No decryption failure is ever logged; the crypto code contains no logging at all.

### Who can access what on the server?

Every request is scoped to your account by the server, never by what your device claims — and the people who run Awaken have no quiet back door either.

**Technical detail — access control (controls 21–26)**

- Every data query is filtered by the account in your session, never by an ID the client sends.
- Every admin route sits behind its own admin check, and the admin console is additionally behind a separate identity gate at the network edge.
- Our automated bug-fixing agent can propose a fix but can't deploy one without a human tapping Execute; its worker uses a separate credential that no user session can reach.
- Deleting an account cascades through every table that belongs to it — verified table by table, including one gap we found and fixed (usage history).
- A written retention and deletion policy (Part 1, above).

### How do you stop injection and cross-site scripting?

**Technical detail — input handling (controls 27–31)**

- All database access goes through an ORM with parameterised queries; there is no raw SQL anywhere in the codebase.
- Every place the app writes HTML was audited (August 2026), and the rule since then is fixed: user text goes through safe text APIs or escaping only.
- One markdown renderer, with raw HTML disabled and dangerous links filtered.
- Request bodies are size-capped.

### How is the server hardened?

**Technical detail — server hardening (controls 32–37)**

- A strict Content Security Policy, enforced in production: scripts, styles, images and fonts load only from our own origin; no inline scripts.
- HSTS, `X-Frame-Options: DENY`, `nosniff` and a same-origin referrer policy on every response.
- Rate limits on waitlist and invite checks, on telemetry, and on every write to your account, so a bug or a hijacked session can't hammer the server.

### How are servers patched and backed up?

On a schedule that's checked on the machines, not just written down — because a schedule nobody installed protects nothing.

**Technical detail — infrastructure (controls 38–42)**

- Patch rules: current Node LTS; base images rebuilt monthly and on every release; dependencies scanned automatically every week, with high and critical issues fixed within 7 days; automatic operating-system security updates with a monthly review.
- Nightly backups are encrypted on the app server *before* they leave it, so the backup machine only ever stores ciphertext. Restore has been proven by actually restoring, not by inspecting files.
- The pepper is backed up separately, under its own passphrase.
- A written incident-response plan. Not yet done, stated plainly: a full restore drill onto a rebuilt server and a rehearsal of the incident plan — both scheduled before our first app test build.

### What runs in my browser?

**Technical detail — client side (controls 43–45)**

- No third-party scripts, fonts or CDNs — every file the app runs comes from us, because one third-party script is one third party who could read your keys.
- The service worker only delivers notifications; it caches nothing, so there's nothing sensitive in it to leak.
- A public vulnerability-disclosure channel: [security.txt](https://journal.everythingawaken.com/.well-known/security.txt).

### What do your logs contain?

**Technical detail — logging and supply chain (controls 46–47)**

- The server writes almost nothing to its logs, and never request bodies, headers or anything decrypted — there's no path for your writing or keys to reach a log.
- Dependency versions are locked and committed.

### How will the phone apps be secured?

The native apps add their own surface, so they get their own checklist, which binds them before release: hardware-sealed key storage, a real-device test of the app lock on iPhone, no cloud backup of your local data or keys, a "sign out other devices" control, server-verified Google/Apple sign-in, a key wiped on uninstall, and an [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) review before the first test build. The apps use no analytics, crash-reporting or tracking libraries.

### How can I check this myself?

We'd rather you verify than trust.

- Open your browser's developer tools, watch the network tab while you write an entry, and see what leaves your device: unreadable ciphertext.
- The standards we follow are public: [Argon2 (RFC 9106)](https://www.rfc-editor.org/rfc/rfc9106.html) · [AES-GCM (NIST SP 800-38D)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) · [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/).
- Our code isn't public yet — we're deciding how to open it, and this line will change when we do.
- Found something? Tell us first through [security.txt](https://journal.everythingawaken.com/.well-known/security.txt).
The legal versions of all this: [Privacy Policy](https://everythingawaken.com/journal/privacy) · [Your Data Stays Yours](https://everythingawaken.com/journal/security) · [Terms](https://everythingawaken.com/journal/terms). The story behind it, question by question: [The Philosophy of Awaken Journal](https://everythingawaken.com/journal/guide/).

## Change log

- **1 October 2026** — First public edition. Privacy Protocol v1.1, Security Protocol v1.2. Same day: the Notes "Awaken Server" plain copy found and removed (Part 1, Notes); the full list of what we can see completed; minimum age set at 14.
We re-verify this page against our code at every app release and every change to either protocol, and update the date at the top when we do.
