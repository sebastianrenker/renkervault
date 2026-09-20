# SECURITY.md — Security model & honest limits

As of: prototype v0.1, after the security-hardening audit of 2026-08-10.
This document describes **what is really protected**, which
trade-offs the prototype makes, and what would mandatorily have to happen before
a real production deployment.

> Why this architecture was deliberately chosen (keyword "chat control"
> / mandatory client-side scanning): see
> [README.md, "Why a tool like RenkerVault?"](README.md#why-a-tool-like-renkervault).

> **In-depth audit documents:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
> (what relay/Tor/cover-traffic/PQ concretely protect — and what not),
> [docs/METADATA.md](docs/METADATA.md) (field-by-field analysis of what the relay
> sees from each envelope), [docs/FINDINGS.md](docs/FINDINGS.md)
> (a structured list of all audit findings with severity, fix, and
> regression test). Automated security tests:
> `client/tests/security/` (39 tests: ratchet, handshake, vault) and
> `server/tests/security/` (12 tests: relay multi-device trust,
> auth flow, bounded storage) — `npm test` in `client/` and `server/` respectively.

---

## 1. What is really end-to-end encrypted?

| Area | Protection | Details |
|---|---|---|
| 1:1 chats | ✅ E2E, Double Ratchet | X3DH hybrid handshake (X25519 + ML-KEM-768, with a one-time prekey when available, see section 4b) → Double Ratchet (X25519 + HKDF-SHA256 + AES-256-GCM). Every message has its own message key (PFS); every reply round trip a fresh root key (post-compromise security). The ratchet implementation was checked and hardened in the security audit of 2026-08-10 (see [docs/FINDINGS.md](docs/FINDINGS.md), FINDING-001/002). |
| Groups | ⚠️ E2E, but structurally weaker than 1:1 | A random 256-bit group key per epoch; every member change verifiably creates a new epoch (removed members read nothing later). **Honest limit (audit 2026-08-10):** no forward-secrecy protection *within* an epoch (a compromised epoch key decrypts all messages of the epoch retroactively) and no cryptographic sender authentication between members. Suitable for small, mutually trusting groups, not for scenarios with potentially malicious members. Details + migration recommendation (sender keys/MLS): [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/FINDINGS.md](docs/FINDINGS.md) FINDING-010. |
| Channels | ⚠ Encrypted, but a weaker trust model | A channel epoch key; owner/admins send. The sender necessarily knows the subscriber list; for large channels the key is widely distributed — more "encrypted broadcast" than confidential communication. |
| Local database | ✅ At-rest | Argon2id (passphrase) → KEK → wraps a random master key → AES-256-GCM over the entire state. HMAC-SHA256 over the ciphertext as tamper protection. No plaintext on disk. |
| Relay server | ✅ Content-blind (no plaintext) — **not** zero-knowledge | Never sees plaintext, but does see metadata: account IDs, public keys, device metadata, connection/timing patterns, opaque envelopes. Auth via Ed25519 challenge-response (passwordless). |

## 2. Duress-alarm system (core feature)

- **Brute force:** 5 failed unlock/login attempts in a short time →
  60 s lockout + red full-screen alarm + entry in the security log. Server-side
  identical logic in the relay (rate limit 30 msg/s per socket, lockout broadcast
  to all devices of the account).
- **New devices:** every additional device is `untrusted` at first and receives
  neither the offline queue nor live-delivered messages until it
  is manually approved by an already-confirmed device. If
  a known device ID reports with a different key → `KEY_MISMATCH` alarm
  (possible impersonation attempt). **Enforced server-side** since the
  security audit of 2026-08-10 — before that, the confirmation requirement was only
  a client-UI convention; the relay itself checked neither on live delivery
  nor on `approve-device`/`revoke-device` the trust status of the caller
  (see [docs/FINDINGS.md](docs/FINDINGS.md), FINDING-004/005/006 — P0,
  fixed, with regression tests in `server/tests/security/relay.test.ts`).
- **DB tampering:** HMAC check on unlock and on retrieval. Failure
  → alarm + optional auto-lockdown (only the alarm screen visible).
- **Duress PIN:** a separate Argon2id hash; the PIN opens an empty
  fake view, the real vault stays locked. Deliberately NO
  visible event is logged.

## 3. Message interactions: metadata transparency

Replies, edits, deletes, forwards, reactions, and presence are
**application events** that run like normal messages over existing 1:1/
group sessions (ratchet- or epoch-key-encrypted) — no
separate server mechanism. Two deliberate trade-offs in this:

- **The reply quote and the "forwarded from" name are envelope metadata**,
  not encrypted payload — just like `msgId`, `fromName`, and the
  file name/size that the relay already sees anyway (see section 1).
  An emoji reaction and the new edit text, by contrast, run like normal
  messages through AES-GCM. For true confidentiality, the
  quote preview would also have to move into the ciphertext payload.
- **Presence ("online"/"last seen") is best-effort and implicitly opt-in-like:**
  the relay itself stores NO contact list or presence —
  clients send each other online/offline signals directly over
  existing 1:1 sessions. Offline signals on closing the app/tab
  are not guaranteed deliverable (no `beforeunload` wait for delivery).
- **Pinned messages are purely local** (not synced between devices/
  contacts) — a deliberate simplification compared to Telegram,
  where pins are visible chat-wide.
- **No automatic link-preview fetch.** URLs are only made clickable,
  NEVER fetched automatically server- or client-side — reloading
  the metadata of a linked page would leak the IP address and the
  read time to a third party (the link operator), independent of
  the end-to-end encryption of the chat itself. A deliberate deviation from
  Telegram's default behavior in favor of privacy.
- **Channels remain demo-only** (see the "What is really encrypted" section);
  a view counter for broadcast messages was therefore not implemented,
  since without real multi-user infrastructure there would be nothing real to count.

## 3a. Sealed sender for 1:1 follow-up messages

From the second message of an existing 1:1 session on, both sides
independently derive a short tag from the shared session secret
(`net/realchat.ts`: `deriveSessionTag`, HKDF over the ratchet shared
secret). The client sends this tag instead of relying on the account ID;
the relay routes by it and **no longer** writes the sender's account ID
into the delivered or cached message
(`server/src/index.js`, case `'send'`) — the recipient instead resolves it
itself via `resolvePeerByTag`.

**Honest limit:** the relay *operator* still knows the sender of a
message, because the `send` command arrives over an already
authenticated WebSocket connection tied to the account ID
— this cannot be avoided without a system of anonymous access credentials (blind
signatures or similar) and is deliberately not implemented
(a considerably larger cryptographic effort, see section 5). What this
feature actually achieves: the account ID no longer lands as plaintext in
the delivered/cached message itself — a data extraction
of the offline queue or a log leak would no longer reveal a sender
for follow-up messages, even if the operator could watch live.
On the very first contact (X3DH envelope), the counterpart does not yet know a tag
and mandatorily needs the account ID to be able to reply at all — there
it stays server-visible as before. Verified via a real
two-browser test (first message `from` visible, second `from: null`,
the recipient still resolves it correctly).

## 4. Known limits of the prototype (deliberate trade-offs)

1. **The Double-Ratchet composition is not audited.** The primitives are
   audited (@noble, hash-wasm, WebCrypto), the protocol composition in
   `ratchet.ts` follows the Signal specification but was not externally
   reviewed. There is currently no maintained audited Signal browser library.
2. ~~X3DH-lite without one-time prekeys~~ **Fixed:** every identity keeps a
   stock of 25 one-time prekeys (`net/realchat.ts`: `topUpOneTimePrekeys`),
   deposited with the relay. A `lookup` with `forHandshake=true`
   consumes exactly ONE of them and removes it server-side immediately from the
   stock (`server/src/index.js`, case `'lookup'`) — pure info lookups
   (`forHandshake=false`, e.g. refreshing a contact name) consume none.
   The handshake then uses three instead of two DH computations
   (`crypto/ratchet.ts`: `handshakeInitiator`/`-Responder`, the third term only
   with a present one-time prekey, distinguished from the
   2-DH variant by its own HKDF info string). If a counterpart's stock is exhausted,
   the handshake automatically and unobtrusively falls back to the 2-DH variant
   (signed prekey alone) — functionally identical to before, but without
   an error case. Verified via a browser test (two real clients) and
   an isolated server test (one-time issuance, no consumption on info lookup,
   clean `null` on empty stock).
3. **Demo peers run in the same browser process** (Nadja/Milan/Brandt/
   Werkstatt Nord/Bulletin) — real crypto, but simulated counterparts, only for
   demonstration. Real contacts/groups (via "add contact") run
   in contrast really over the relay between independent client instances,
   including persisted sessions (see `net/realchat.ts`).
4. **Demo ratchet session state is NOT persisted** (deliberate — every
   restart renegotiates, safety numbers stay stable). **Real
   sessions and group keys, in contrast, ARE persisted** (encrypted
   in the vault), since otherwise two real conversation partners would
   diverge after a restart.
5. **Memory/storage hardening (audit 2026-08-10):** the master key is now,
   on locking/destroying the vault, explicitly overwritten with zeros in the JS heap
   (`crypto/vault.ts`, `zero()`) before the reference drops;
   `destroyVault()` overwrites the `localStorage` slot three times with
   random data before removing it. **Honestly documented limit:**
   no guarantee — V8's garbage collector and the WebCrypto implementation
   can hold their own copies unreachable from JS, and the
   storage engine (LevelDB/SQLite backing) can still contain
   older copies through compaction. Details: [docs/FINDINGS.md](docs/FINDINGS.md),
   FINDING-008/009.
6. **localStorage instead of SQLCipher:** a browser prototype. The key model
   (Argon2id → KEK → master key → AES-GCM + HMAC) is transferable identically;
   a desktop variant (Tauri) should use SQLCipher + OS keychain.
   **Deliberately not yet implemented** (hardening roadmap point 8): this is not a
   cryptography gap — the vault content is already fully AES-GCM-
   encrypted, independent of the storage location. A real migration would need
   Rust-SQLite/SQLCipher bindings + Tauri IPC commands + a migration path
   for existing `localStorage` vaults, and could only be verified correctly on an
   actually started Tauri process — not something to take responsibility for without
   that test.
   ~~Hardware-bound wrap layer (hardening roadmap point 6)~~ — for
   Windows desktop partly implemented since this update: `src-tauri/src/dpapi.rs`
   wraps `CryptProtectData`/`CryptUnprotectData` (Windows DPAPI, bound to the
   Windows user account + device) as Tauri commands. `crypto/vault.ts`
   detects at runtime via `isTauri()` whether a native desktop environment
   is running, and then additionally places the already-KEK-wrapped master key in
   a DPAPI layer (`dpapiWrapped: true` in the vault file) — a
   copied vault file is then, on another device/Windows account,
   no longer decryptable even with the correct passphrase (a new
   `UnlockResult` reason `device-mismatch`, deliberately NOT counted as a failed
   attempt in the brute-force counter, since it is not a passphrase problem). In the
   browser/Android build the behavior stays unchanged (no DPAPI
   available, `dpapiWrapped: false`, the pure Argon2id path as before) —
   fully backward-compatible with existing vaults.
   **Test coverage:** the native DPAPI layer itself is verified via four real
   `cargo test` cases against the actual Windows API
   (round trip, no plaintext in the protected blob, failure on
   tampering, empty input). The browser fallback path (no Tauri) is
   verified via a real end-to-end test (create → lock →
   unlock). **Not verifiable in this environment:** the full
   round trip *inside* a running Tauri window (native WebView2
   window, not controllable by the browser-automation tools available here)
   — to be caught up manually on real Windows with
   `npm run tauri dev` before production use. macOS (Keychain) and Android
   (Keystore) are analogously conceivable but not implemented.
7. **The relay holds state only in RAM** (prototype): accounts/queues are lost on
   restart. Production: PostgreSQL for metadata, persistent
   encrypted offline queues. **Since the audit of 2026-08-10, bounded
   instead of unbounded:** a hard upper limit for the total number of managed
   accounts (`MAX_TRACKED_USERS`, 200,000) as well as a periodic sweep
   (every 10 minutes) removes expired queue entries (TTL
   14 days) and device-less phantom accounts — prevents unbounded
   memory growth from messages to freely invented target userIds
   (see [docs/FINDINGS.md](docs/FINDINGS.md), FINDING-007). A real
   persistence layer nevertheless remains open — the bounded-RAM behavior is
   a safeguard against resource exhaustion, not a substitute for
   restart persistence.
8. **Metadata:** the relay sees who-with-whom-when (routing). ~~Protection
   against it (sealed sender...) is not implemented~~ — for 1:1 follow-up
   messages partly implemented since this update (section 3a).
   ~~Padding and cover traffic remain open~~ — also implemented since this update
   (section 4g). Still open: the relay *operator* still sees
   live which authenticated connection sends a
   `send` message at all (the timing of the connection setup itself); padding/
   cover traffic obscure only the size and send frequency of the messages
   afterwards, not the fact of the connection itself.
9. **Web delivery:** a web app can be delivered compromised by the
   server (malicious JS). Serious use needs signed
   desktop/mobile builds (Tauri/Capacitor, see README "Deployment").
10. **Argon2id parameters** (64 MiB, t=4, see `crypto/primitives.ts`) are a
   trade-off between security and unlock latency on weaker
   hardware; for a dedicated production deployment, calibrate further per OWASP and
   target hardware.
11. **No protection against a compromised endpoint.** Malware/keyloggers on the
    device see everything — no E2E encryption can prevent that.
12. **Attachment/voice-message size:** 1.2 MB of raw data per attachment (a prototype
    upper limit, see `MAX_FILE_BYTES` in `ui/App.tsx` and `MAX_MSG_BYTES` in
    `server/src/index.js`) — sufficient for images/short voice messages,
    not for videos.
13. **Relay rate limiting is deliberately kept simple:** a connection
    cap per IP (20), an auth timeout (15 s), a per-socket message limit
    (30/s) plus two additional, **account-based** limits (independent of
    the number of simultaneously connected devices of the same account) — a
    send limit (300 messages/minute, prevents flooding the
    queue of a single target account) and a handshake-lookup limit
    (20 per 5 minutes, prevents targeted draining of a victim's one-time-prekey
    stock, see section 4 point 2) — protect against
    trivial resource exhaustion by a single attacker. There is
    still no protection against distributed attacks (DDoS) from many IPs —
    for that an upstream reverse proxy/CDN with DDoS protection is needed.
    Concrete, tiered options (ufw connection limit, fail2ban jail,
    CDN fronting) are now documented in `deploy/DEPLOYMENT.md`, section
    "DDoS protection"; an optional Caddy rate-limit block in
    `deploy/Caddyfile` (needs an `xcaddy` custom build with the
    `caddy-ratelimit` plugin; vanilla Caddy has no built-in
    rate limiting).

## 4a. TLS / hosting to make it reachable for others

The relay now supports both native TLS (`TLS_CERT_FILE`/`TLS_KEY_FILE`)
and the recommended operation behind a reverse proxy (Caddy with an
automatic Let's Encrypt certificate). A full step-by-step
guide including systemd hardening: [deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md).
**Important:** `ws://` to a NON-local host transmits the initial
handshake and all routing metadata in plaintext — for anything other than
`localhost`, `wss://` with a valid certificate is mandatory. The app now warns
about this actively in the settings too.

**TLS certificate pinning (hardening roadmap point 7):** for the
Android variant there is now a commentable `<pin-set>` template
in `android/app/src/main/res/xml/network_security_config.xml`. NOT active by default,
because pinning requires a hard-compiled domain, but
RenkerVault's relay address is freely selectable in the settings —
sensible only for operators who ship their own branded app variant with
exactly one fixed relay (a guide incl. the `openssl` command to
compute the pin is directly in the file). For the browser prototype and the
Tauri desktop variant (which uses the system WebView) there is no
public API for TLS pinning — a platform limit, not a missing
feature of this project.

For maximum IP anonymity (neither the server nor a network observer
sees the real IP address of the conversation partners) there is additionally
**path 3: Tor hidden service** (`deploy/torrc.snippet` +
[deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md)) — the relay then runs
exclusively under an `.onion` address, entirely without a public
DNS name or open port.

## 4b. Protection against quantum computers (post-quantum hybrid handshake)

The initial key exchange (X3DH-lite) is, since this update,
**hybrid**: classical X25519 ECDH **plus** ML-KEM-768 (FIPS 203, formerly
Kyber; an audited implementation from `@noble/post-quantum`), both
shared secrets mixed together through HKDF-SHA256 (`crypto/pq.ts`,
`crypto/ratchet.ts`). This is the same approach that Signal uses in production
under the name "PQXDH".

- **Why at all, if today's quantum computers cannot do this yet?**
  Because of "harvest now, decrypt later" (HNDL): an attacker can already today
  store recorded ciphertext and only decrypt it in some years with a
  sufficiently large quantum computer. The handshake must therefore be
  quantum-safe *today*, so that today's messages stay protected in ten
  years too.
- **What is NOT PQ-protected:** only the first-contact handshake uses ML-KEM.
  The ongoing Double-Ratchet steps afterwards still rely on
  classical X25519 ECDH (as in Signal too) — a deliberate,
  industry-standard limit, not an oversight. Full protection of the entire
  ratchet against quantum attacks is currently not an established standard.
- **Even if X25519 were broken in the future**, the first contact would stay
  secure through ML-KEM-768, as long as its mathematical assumption
  (module-LWE) holds — hence "hybrid": it suffices that *one* of the two
  schemes holds.
- Verified via a real two-browser test over the relay (see section 1).

## 4c. Burn session (immediate, irreversible deletion)

Every chat has a 🔥 button (double-click to confirm) that immediately and
irreversibly deletes the complete local message history. For real
1:1 contacts, the encryption session (ratchet state)
and the contact itself are additionally removed — a renewed contact requires a
completely new handshake, nothing of the old session is left over.
This corresponds to the "as if it never happened" principle of OnionShare/Tor:
after burning, no proof exists anymore that the conversation
took place (apart from the fact that the relay only ever sees metadata,
never plaintext — see section 1).

## 4d. Why there is NO one-time pad and NO "quantum random generator"

These two concepts were deliberately examined and NOT implemented —
here the honest reasons, instead of silently omitting them:

- **One-time pad (OTP):** mathematically perfectly secure (Shannon), but only
  under a condition that is almost never met in practice: the
  key must be exactly as long as the message, **truly** random,
  and must be reused **not even once**. For chat use
  (potentially arbitrarily many messages), a huge amount of
  key material would have to be securely exchanged in advance (e.g. in person via a USB
  stick, as described in the video as a "codebook") — and the slightest
  reuse of a block breaks the entire security. The
  Double-Ratchet approach that RenkerVault uses instead achieves a
  protection comparable in practice (every message its own key,
  see section 1), without the key-exchange problem of the OTP — hence
  no OTP option in the app.
- **"Quantum random generator" (QRNG):** a true QRNG needs special
  hardware (e.g. the quantum noise of a photodiode) and cannot be realized in
  software/in the browser — any software claiming to generate
  "quantum randomness" without reading such hardware makes a
  false claim. RenkerVault instead uses `crypto.getRandomValues()`
  (a cryptographically secure pseudo-random generator, CSPRNG), which is the
  correct and, in cryptographic practice (incl. Signal, TLS, etc.),
  standard approach. There is no known practical security gain
  from true quantum randomness over a CSPRNG for this purpose.

## 4e. Compatibility with hardened/alternative operating systems

The Android app has **no dependency on Google Play Services or
Firebase** (no push service, no analytics SDKs) and therefore works
unchanged on de-Googled systems such as **GrapheneOS**. A
`network_security_config.xml` additionally enforces `wss://` for every host
except `localhost`/`127.0.0.1`/`10.0.2.2` (the emulator alias) — plaintext `ws://`
is only allowed on your own device, defense-in-depth to the app's own
warning in the settings.

## 4f. Dependency pinning & supply-chain check

The highest priority of the [hardening roadmap](docs/inventions/RenkerVault-Haertungs-Roadmap.md)
on the technical track: a compromised transitive dependency
of `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, or
`hash-wasm` would render every other hardening measure worthless (real
precedents: `event-stream` 2018, `ua-parser-js` 2021).

- **Exact version pins:** all direct dependencies in `client/package.json`
  and `server/package.json` are fixed to exact, currently installed versions
  (no more `^`/`~` ranges) — an `npm install` therefore no longer
  automatically pulls new minor/patch versions that could flow unchecked into the project.
  `package-lock.json` additionally remains as a second,
  transitive pinning layer.
- **`npm audit` result (as of this update):** server dependencies
  0 findings. Client dependencies: 6 findings in the pure build-tooling chain
  (esbuild/vite/postcss/tar/nanoid/brace-expansion, all transitive via Vite),
  **none** in the crypto-relevant runtime packages
  (`@noble/*`, `hash-wasm`, `react`, `@capacitor/*`, `@tauri-apps/*`). Four
  of them (brace-expansion, nanoid, postcss, tar) are fixed without a breaking change.
- **Deliberately left open:** the remaining two findings (`esbuild`
  moderate, `vite` high — Vite ≤6.4.2 depends on a vulnerable
  esbuild version) would affect exclusively the local dev server
  (`npm run dev`: a malicious website could make requests to the dev server
  in the developer's browser and read responses —
  NEVER affects the production build or end users). The fix requires a
  major jump to Vite 8, which `@vitejs/plugin-react` (currently 4.7.0) does not
  yet officially support as a peer dependency (the range ends at `^7.0.0`).
  A test showed: the jump can be forced with `--force` and the
  build/dev server even run without error afterwards — but every future
  `npm install` without `--force` would then break permanently with an
  ERESOLVE error. This trade (closing a dev-only gap against a
  broken default installation flow for every future checkout) was
  deliberately NOT made — instead Vite stays pinned at 5.4.21 until
  `@vitejs/plugin-react` officially supports Vite 8. Re-check as soon as
  a new `@vitejs/plugin-react` version appears.
- **No automated, recurring check:** there is (as of now)
  no CI pipeline that runs `npm audit` automatically on every build —
  the prototype has no CI configured. Until then: run `npm audit` manually in
  `client/` and `server/` again before every release.

## 4g. Padding & cover traffic (metadata minimization, continuation of 3a/4f)

Hardening roadmap point 4, justified directly from the README background section
(goal: surveillance resistance, not just content confidentiality).

- **Padding (`crypto/padding.ts`):** every message — text, file,
  group message, and also the internal markers (`presence`, `deleted`,
  `reaction`) — is, before AES-GCM encryption, padded to one of nine
  fixed size buckets (64 B – 1.25 MiB). The relay thus sees
  only one of a few ciphertext sizes instead of the exact
  plaintext length. An ISO/IEC-7816-4-like scheme (0x80 marker byte +
  null bytes), no custom cryptography — pure byte manipulation on
  already-finished plaintext. 40 isolated unit checks (round trip at all
  bucket boundaries, empty message, overflow, corrupt data) plus
  end-to-end verification over two real browser clients.
- **Cover traffic (`net/realchat.ts`, `ui/App.tsx`):** Poisson-like
  jittered dummy messages (mean 60 s, 20–180 s spread) to
  randomly chosen, already-known contacts — on by default, disableable in
  the settings. Crucially: these run as perfectly normal
  `kind:'text'` envelopes; the distinguishing marker is
  EXCLUSIVELY in the end-to-end-encrypted payload (a fixed
  32-byte SHA-256 value), NOT in a separate envelope field — otherwise
  the relay could trivially filter out cover messages by the plaintext field,
  exactly what the mechanism is meant to prevent. The recipient detects
  and discards them silently on decryption (no UI entry, no
  unread bump). Verified via a real two-browser test with a temporarily
  shortened interval: multiple bidirectional cover-traffic exchanges
  observed, the chat history afterwards still shows exclusively the
  actually sent messages.
- **Honest limit (identical to candidate D of the security-invention
  analysis):** with very few contacts per account, the statistical
  obscuring stays weaker than with many. Costs some
  bandwidth/battery continuously, even when nobody is actively chatting. Obscures the size and
  send frequency — does NOT obscure that an authenticated
  connection to the relay exists at all (see point 8 above).

## 4h. Reproducible builds (a precursor to signed builds, hardening roadmap point 2)

- **Exact version pins on the Rust/Tauri side too:**
  `src-tauri/Cargo.toml` now also fixes exact versions (`=x.y.z`
  instead of caret ranges) for `tauri`, `tauri-build`, `tauri-plugin-log`,
  `serde`, `serde_json`, `log`. Additionally, `src-tauri/rust-toolchain.toml`
  fixes the exact Rust toolchain version (`rustup` downloads it automatically
  on demand) — without this file, different machines with
  different `rustc` versions could produce different binaries
  from the same source code.
- **Checksums (`client/gen-checksums.mjs`, `npm run checksums`):**
  generates `SHA256SUMS.txt` over all present build artifacts (web dist,
  Tauri bundle, Android APK/AAB). Does NOT replace a code signature — does
  not protect against an attacker who controls both the artifact and the checksum
  file at delivery. The point: whoever reproduces the build
  themselves can compare their hash against an independently published
  one (e.g. a GPG-signed release entry).
- **Deliberately NOT implemented: a real code signature.** That needs real
  certificates (Windows Authenticode, Apple Developer Program, Android
  Play signing) — organizational prerequisites (registration,
  identity verification, ongoing costs) that no code step can replace.
  Build and toolchain reproducibility are the precursor to it, which now
  stands; the actual signature remains open in section 5.

## 5. Mandatory before production use

- An external cryptography audit (in particular `crypto/ratchet.ts`, `crypto/vault.ts`)
  **or** replacement with native libsignal (Tauri/FFI).
- ~~Full X3DH with signed prekeys + one-time prekeys~~ — implemented since this
  update (section 4, point 2).
- TLS (wss://) is available and should be mandatorily used for any operation outside
  `localhost` (see deploy/DEPLOYMENT.md).
  ~~Certificate pinning~~ — an Android template present since this update
  (section 4a), browser/Tauri remain open for lack of a platform API.
  ~~DDoS protection in front of the reverse proxy~~ — tiered options documented
  since this update (deploy/DEPLOYMENT.md), real protection against distributed
  attacks remains possible only via an upstream CDN service.
  Still open: a persistent server store (PostgreSQL).
- ~~Sealed-sender-like metadata minimization~~ — for 1:1 follow-up messages
  implemented since this update (section 3a), ~~padding and cover traffic~~
  also (section 4g). First-contact messages and anonymity
  toward the live-authenticating relay operator itself remain
  open (that would need anonymous access credentials).
- Signed client builds — a ~~reproducible~~ build/toolchain base present since
  this update (section 4h), the actual certificate
  signature (Windows/macOS/Android) needs real certificates to be
  procured organizationally.
- ~~Dependency pinning + supply-chain check~~ — implemented since this update
  (section 4f).
- A hardware-bound vault key and SQLCipher+OS keychain for the
  Tauri desktop variant — the architecture is sketched (section 4 point 6),
  implementation deliberately deferred (verifiable only on real hardware/a
  running Tauri process, see docs/inventions/
  RenkerVault-Haertungs-Roadmap.md, points 6 and 8).
- A threat-model review (formal), a pen test of the relay — a scope document already
  exists: [docs/inventions/RenkerVault-Audit-Vorbereitung.md](docs/inventions/RenkerVault-Audit-Vorbereitung.md).
- Migration of the group encryption to an established construction
  (sender keys/MLS) — the current model is sufficient for small, trusting groups,
  not for scenarios with potentially malicious members
  (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).
- An **external** cryptography audit remains open despite the internal
  security-hardening audit of 2026-08-10 — for details on what this
  internal audit covered and what not, see
  [docs/THREAT_MODEL.md, "Audited vs. non-audited
  parts"](docs/THREAT_MODEL.md#audited-vs-non-audited-parts).

## 6. Reporting security vulnerabilities

A prototype — please send findings directly as an issue/note to the maintainer
(Renker Industries, internal).
