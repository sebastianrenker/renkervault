# SECURITY_AUDIT.md — Phase 1: Technical security inventory

As of: 2026-08-11. This is a **pure analysis** — no production
code was changed in this pass. Basis: a full read
of `client/src/`, `client/src-tauri/`, `server/src/`, all tests,
`package.json`/lockfiles/`Cargo.toml`, `tauri.conf.json`,
build/release configuration, README.md, SECURITY.md, and the already
existing audit documents from a previous hardening pass
(`docs/FINDINGS.md`, `docs/THREAT_MODEL.md`, `docs/METADATA.md`).

**Important context for this document:** on 2026-08-10 there was already
an internal hardening audit that fixed two critical bugs (see
[docs/FINDINGS.md](docs/FINDINGS.md), FINDING-001 to FINDING-012):

1. Double-Ratchet `decrypt()` mutated the session state before the
   AEAD authentication was checked (state corruption possible through a
   single forged packet).
2. Relay `approve-device`/`revoke-device` did not check whether the caller
   itself is a trusted device (a complete bypass of the
   multi-device trust model).

These are **already fixed and covered by regression tests** (51
tests: 39 in `client/tests/security/`, 12 in `server/tests/security/`).
This new audit builds on that — it does not repeat these two findings
as "new", but checks what has been overlooked since, and goes into
depth on topics the last pass did not, or only superficially,
address: device-pairing UX, CI/supply-chain automation,
fuzzing, Tauri CSP/IPC hardening, backup/crash recovery, process/log access.

---

## 0. The most important single finding of this pass (up front)

**There is currently no client-side "add a new device to an existing account"
flow.** `Onboarding.tsx` → `CreateVault` generates on every
call a completely new, independent identity: a new `userId`
(`newUserId()`), a new X25519 identity key pair, a new
Ed25519 key pair, a new prekey, a new `deviceId` (`uid('dev-')`) — all
together as one bundle. There is no input field to adopt an *existing*
`userId`, no QR provisioning flow, no
Signal-like "sign in as a linked device" screen.

That means: the server-side multi-device trust model
(`approve-device`/`revoke-device`, see FINDING-004/005/006 in the last
audit) is a fully working and now correctly
enforced **server protocol feature**, but has **no reachable
entry point in the current client UI**. The only practical way
to create two "devices" with the same `userId` would be to manually copy the complete
vault file (the `localStorage` entry that contains `Identity` including all
private keys AND the `deviceId`) onto a second
device — but that would appear as the **same** device
(an identical `deviceId`, an identical `edPub`), not as a new,
confirmation-requiring device, and would additionally mean that private
identity keys are shared between devices — architecturally the
opposite of Signal's "every device has its own keys" model.

**Assessment:** this is not a security hole in the narrower sense (nothing
becomes compromisable through it that would not already be so) — it is a
**missing function** that, however, effectively makes phase 6 of this audit task
("hardening the device-pairing system") moot as long as it is not
built. Recommendation for phase 14: before device pairing can be "hardened",
it must first exist as a feature — with a
cryptographically correct provisioning protocol (see section 8
below for a concrete draft, oriented at Signal's
device-linking procedure). For details see [section 6](#6-device-pairing--analysis-of-the-as-is-state).

---

## 1. Threat model — 14 attackers

Severity scale: **Critical** (breaks confidentiality/integrity
of the core promise), **High** (breaks an important secondary property such
as availability or multi-device trust), **Medium** (a metadata/
privacy restriction), **Low** (theoretical, high effort or
low damage).

### 1. Malicious relay server

| | |
|---|---|
| **Protected assets** | Message content, file attachments, group membership |
| **Attack vector** | The operator fully controls `server/src/index.js` — can read, alter, delay, duplicate, drop, reorder every message, deliver false lookup responses |
| **Current protection** | E2E encryption (Double Ratchet, group keys) — the server never sees plaintext. Double-Ratchet `decrypt()` now (after the FINDING-001 fix) safely discards manipulated/forged messages without corrupting the session state. `approve-device`/`revoke-device`/live delivery are trust-checked since FINDING-004/005. |
| **Remaining risk** | The relay can selectively drop messages (an availability, not a confidentiality breach) — not directly detectable by the sender (no delivery-confirmation/sequence-number mechanism beyond the ratchet-internal counter). The relay still sees considerable metadata (see the metadata section in THREAT_MODEL.md). An X3DH downgrade to "lite" mode through selectively withholding OTPKs remains possible (FINDING-003, only heuristically detected). |
| **Severity** | Medium (core confidentiality holds; availability/metadata/downgrade remain residual risks) |
| **Concrete improvement** | Delivery confirmations with continuous, client-checked sequence numbers per chat (detects selective dropping); cryptographically binding prekey-bundle signatures with a freshness proof against the downgrade (see FINDING-003). |

### 2. Passive network attacker

| | |
|---|---|
| **Protected assets** | Message content, connection metadata |
| **Attack vector** | Observes traffic between client and relay (ISP, Wi-Fi eavesdropper, network operator) |
| **Current protection** | TLS (`wss://`) mandatory outside `localhost` (the app actively warns on unencrypted `ws://` to remote hosts, see `Settings`). Envelope padding (9 size buckets) obscures the exact plaintext length. Cover traffic partly obscures timing/frequency. |
| **Remaining risk** | Without TLS (a deliberately allowed local development option) fully visible in plaintext. Even with TLS: connection-setup timing, packet-size metadata at the TCP level (TLS encrypts content, not packet sizes/timing fully), IP addresses of both ends visible (except when running as a Tor hidden service). |
| **Severity** | Low with correct `wss://` operation; Critical with accidental `ws://` operation outside localhost (mitigated by the app warning, but not technically prevented — the setting can still be set that way) |
| **Concrete improvement** | Hard-block `ws://` to non-localhost hosts instead of only warning (downgrade from warning to refusal); evaluate TLS certificate pinning for Tauri/browser too, once platform APIs allow it (currently only an Android template present). |

### 3. Active network attacker (MITM)

| | |
|---|---|
| **Protected assets** | Handshake integrity, identity binding |
| **Attack vector** | Can terminate the TLS connection (if TLS itself is compromised/wrongly validated), inject/modify packets |
| **Current protection** | TLS protects the transport (standard certificate validation of the browser/WebView, no pinning except the Android template). X3DH binds the session to identity keys; safety numbers allow manual out-of-band verification. |
| **Remaining risk** | Without certificate pinning, an attacker with a TLS certificate forgery accepted by the OS/browser (e.g. issued by a compromised/enforced root CA) remains theoretically able to terminate the WebSocket channel and impersonate the relay — but, because of E2E encryption, still cannot read message content, only act like a malicious relay (see point 1). Without active safety-number verification by users, an identity-key substitution on the very first contact (trust-on-first-use) stays undetected. |
| **Severity** | Medium (TOFU is a deliberate, documented design decision, not a bug — but users rarely verify safety numbers in experience) |
| **Concrete improvement** | Require safety-number verification more prominently in the UI (e.g. an "unverified" badge permanently visible instead of only in the contact detail); evaluate TLS pinning for desktop/web once platform APIs allow it. |

### 4. Compromised user account (stolen/guessed userId + access to a device)

| | |
|---|---|
| **Protected assets** | Account identity, multi-device trust |
| **Attack vector** | The attacker knows the (deliberately shareable) `userId` of a victim and registers itself via `hello` as a "device" of this account |
| **Current protection** | Since FINDING-004/005 (last audit): such a device is `untrusted`, receives neither live nor offline delivery, cannot self-authorize, and cannot remove other devices. |
| **Remaining risk** | As described in section 0: since there is currently **no client flow that legitimately adds a second device to an existing account**, the account owner itself effectively also has no way to confirm a waiting device — the UI does show waiting devices in the device list (`SecurityCenter.tsx`) and an `approve` button, but the account owner would have to recognize that the request does NOT originate from itself (a pure attention question, no technical protection beyond the already-present `NEW_DEVICE` alarm message). |
| **Severity** | High → reduced by the last audit from Critical to High (no more automatic access, but a social-engineering residual risk remains: a user could mistakenly confirm a foreign request) |
| **Concrete improvement** | Extend the device-confirmation dialog with a security feature that makes foreign requests harder to make plausible than one's own (e.g. a short confirmation code known only to the real second device instead of a pure "yes/no" — that is exactly the core of a real pairing protocol, see section 6). |

### 5. Compromised endpoint (malware/keylogger/physical access while unlocked)

| | |
|---|---|
| **Protected assets** | Everything — plaintext messages, master key, passphrase input |
| **Attack vector** | Full access to the process while the vault is unlocked |
| **Current protection** | None (and none conceivable) — E2E encryption fundamentally cannot prevent endpoint compromise. Master-key zeroization on locking (FINDING-008) shortens the window AFTER locking. |
| **Remaining risk** | Full — documented, not solvable. |
| **Severity** | Critical, but architecturally unsolvable (any software on a compromised device is affected) |
| **Concrete improvement** | Check/tighten auto-lock after inactivity (currently present? see the code-review point in section 5 below); OS-keychain integration would not shrink the window for master-key extraction from the JS heap, since the key must be in memory during active use anyway. |

### 6. Compromised peer (the conversation partner itself is malicious or its device is compromised)

| | |
|---|---|
| **Protected assets** | Messages to OTHER contacts/group members, one's own identity |
| **Attack vector** | The peer sees by definition all plaintext messages exchanged with it (that is not a bug — every E2E chat works that way). For groups: a member holds the full epoch key. |
| **Current protection** | 1:1: compromise of a peer reveals only its own conversation, not other contacts (each 1:1 session has its own ratchet chain). Groups: member removal rotates the epoch key correctly (verified, `rotateRealGroup`). |
| **Remaining risk** | **In groups:** a malicious but not yet removed member can forge messages that appear in the UI as "from person X" — the epoch key is symmetric, there is no per-member sender signature (FINDING-010). A malicious member can additionally have passed the epoch key to third parties after its own exclusion, before the rotation takes effect (inherent to any shared-key model). |
| **Severity** | Medium (1:1) / High (groups with potentially not fully trusted members) |
| **Concrete improvement** | Migration of the group encryption to sender keys/MLS (see section 7) for real sender authentication. |

### 7. Tampered local storage

| | |
|---|---|
| **Protected assets** | Vault integrity, confidentiality of stored data |
| **Attack vector** | Direct file access to the `localStorage` backing store (e.g. via other software on the same device, or recovery from a backup) |
| **Current protection** | HMAC-SHA256 over the ciphertext (`checkIntegrity()`, checked before every unlock) reliably detects tampering — the result `tampered`. AES-GCM itself is additionally authenticated (a double safeguard). |
| **Remaining risk** | Detection yes, recovery no — a tampered file is simply no longer unlockable (no differentiated recovery, no diff against a backup). No protection against a **replay** of an older but valid (untampered) vault snapshot — the HMAC of an older but intact version still checks "ok" correctly, so the system cannot detect whether a valid file was deliberately replaced by an OLDER valid version (a rollback attack on the vault itself, not on the ratchet). |
| **Severity** | Medium — tamper detection works, rollback-to-an-old-valid-version stays undetected (no monotonic/generation counter in the vault format) |
| **Concrete improvement** | Add a monotonically increasing generation counter to the `VaultFile` format (incremented on every `saveVault`), checked on every unlock against a last-seen value — prevents the unnoticed replay of an older but validly signed version. |

### 8. Compromised dependency

| | |
|---|---|
| **Protected assets** | Everything — a compromised crypto library can undermine every guarantee |
| **Attack vector** | Malicious code in `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, `hash-wasm`, `ws`, `tauri`, or similar — directly or via a compromised transitive dependency |
| **Current protection** | Exact version pins (no `^`/`~`) in `package.json` (client + server) and `Cargo.toml`. `npm audit`: 0 findings in both packages (production dependencies). No cryptography implementation of its own — only established, widely used libraries. |
| **Remaining risk** | Pinning protects against automatically pulling compromised NEW versions, not against a version already compromised at the pin time. **No automated, recurring `npm audit`/CI check** — findings would only surface on manual review (see section 9, no `.github/workflows` present). No SBOM. No signature/provenance check of npm packages themselves (npm has no mandatory package signing). |
| **Severity** | High (not a technical fault in the project itself, but a real, unaddressed process gap — real precedents: `event-stream` 2018, `ua-parser-js` 2021, `xz-utils` 2024) |
| **Concrete improvement** | A CI pipeline with `npm audit --audit-level=high` as a mandatory check, Dependabot/Renovate for controlled update PRs instead of manual pins, SBOM generation (see phase 9/10 below). |

### 9. Supply-chain attacker (compromised build/release system)

| | |
|---|---|
| **Protected assets** | Integrity of the shipped binaries (installer, APK) |
| **Attack vector** | An attacker with access to the build machine or the GitHub release account could ship manipulated binaries |
| **Current protection** | `SHA256SUMS.txt` is generated for build artifacts (`client/gen-checksums.mjs`). Rust/Node toolchain versions are pinned (a precursor to reproducible builds). |
| **Remaining risk** | **No code signature** (Windows Authenticode, Apple Developer, Android Play signing) — already documented as open in SECURITY.md. Without a signature, a user cannot cryptographically verify the origin of an installer, only the hash against a checksum file (also published by the same operator, so not independent). No build-provenance proof (e.g. SLSA/Sigstore), no GitHub Actions artifact attestation. No CI pipeline at all (`.github/workflows` does not exist) — releases are currently built and uploaded manually locally, which additionally reduces the trust model to "trust the maintainer's machine", without a traceable, reproducible CI build log. |
| **Severity** | High |
| **Concrete improvement** | A release build via GitHub Actions instead of locally (a traceable build log as a trust anchor), GitHub artifact attestations (free, builds on Sigstore, no own certificate needed), and, in perspective, a real code signature. |

### 10. Attacker with access to backups

| | |
|---|---|
| **Protected assets** | Vault content in backups (e.g. cloud sync of the browser profile, Windows file backup) |
| **Attack vector** | The `localStorage` backing file ends up unasked in system/cloud backups (e.g. browser sync, Windows system restore, WebView2 profile backup) |
| **Current protection** | The vault content is already fully AES-256-GCM-encrypted — a backup never contains plaintext, independent of the backup mechanism. |
| **Remaining risk** | An attacker with access to a backup AND the passphrase can unlock the vault just as on the original device — there is (deliberately, see section 0) no device/hardware binding that prevents this, EXCEPT on Windows desktop with the DPAPI wrap layer enabled (there, unlocking fails with `device-mismatch` if the file was copied to another Windows account/device). In the browser/Android context (no DPAPI), a backup is fully portable — pure passphrase knowledge suffices. That is functionally identical to "the passphrase is the only protection", which is acceptable with a sufficiently strong passphrase but not to be taken for granted (no minimum requirement except 8-character length, see `Onboarding.tsx`). |
| **Severity** | Medium — depending on passphrase strength, which is currently only checked for minimum length (8 characters), not for entropy/reuse |
| **Concrete improvement** | A passphrase strength indicator (e.g. a zxcvbn-like estimate) in the onboarding instead of a pure length check; catch up DPAPI-like hardware binding for macOS (Keychain) and Linux (Secret Service) too, as already documented as open in SECURITY.md. |

### 11. Attacker with access to the running process (debugger, memory dump)

| | |
|---|---|
| **Protected assets** | Master key, ratchet session keys, plaintext in memory |
| **Attack vector** | Debugger attach, core dump, swap-file analysis while the app runs |
| **Current protection** | Master-key zeroization on locking (FINDING-008) — only relevant for the time AFTER locking. During UNLOCKED operation: no protection (technically barely possible in JavaScript, see below). |
| **Remaining risk** | While the vault is unlocked, the master key, all active ratchet chain keys, and decrypted plaintexts are necessarily in the JS heap — any process debugger/memory dump at that time compromises everything. This is **not a RenkerVault-specific weakness**, but a fundamental limit of any JavaScript runtime: there is no equivalent to Rust's `zeroize`, `mlock()` (protecting memory from swapping), or guaranteed stack/heap cleanup. V8's garbage collector can copy objects before they are freed, and the WebCrypto implementation holds imported keys internally in a form unreachable from JS. |
| **Severity** | Critical during active use, but architecturally not solvable within JavaScript/browser/WebView |
| **Concrete improvement** | Document honestly (see section 5 below — SECURITY.md must name this explicitly as a JS limit, not sell it as "solved"). For the Tauri variant: move the most security-critical operations (master-key handling) into the Rust backend process in perspective (significantly stronger memory control than in the WebView JS context) — a larger architecture project, not short-term. |

### 12. Attacker with access to logs

| | |
|---|---|
| **Protected assets** | Metadata, potentially secrets in error messages |
| **Attack vector** | Access to server `console.log` output, the client-side browser DevTools console, Tauri `tauri-plugin-log` files |
| **Current protection** | The server logs only `[GUARD] Lockout for <userId>`, `[ERR] <err.message>` — no payload/key logs found. The client, per the previous audit, has no debug logs with secrets (comment/log cleanup was part of the last hardening pass). |
| **Remaining risk** | `console.error('[ERR]', err.message)` in the server could, on certain error paths (e.g. a `JSON.parse` error with the original string in the error message, or a future added error path), accidentally land payload fragments in logs — currently not the case, but not safeguarded by a structural rule (e.g. a linter rule against `console.log(msg)` with a raw message object), only by code review. `tauri-plugin-log` is included, but it was not checked whether/where it writes by default and whether sensitive IPC arguments could be logged. |
| **Severity** | Low (currently no found leakage) to Medium (no structural safeguard against future regressions) |
| **Concrete improvement** | A lint rule/code-review checklist: never pass raw envelope/message objects to `console.*`, only selected, known-insensitive fields. Restrict the `tauri-plugin-log` configuration explicitly to debug builds or check the log level/target for release builds. |

### 13. Malicious group administrator

| | |
|---|---|
| **Protected assets** | Group membership, message integrity within the group |
| **Attack vector** | An `owner`/`admin` member (see `MemberPermissions`: `canRemove`, `canInvite`, `canPin`) can remove/add members and has full access to the current epoch key |
| **Current protection** | A role model (`owner`/`admin`/`member`) with granular permissions exists in the data model (`state/types.ts`: `Member`, `MemberPermissions`). Epoch rotation on member change verified correctly. |
| **Remaining risk** | The permission check (`canRemove` etc.) is purely **client-side** (in the UI) — there is no server-side or cryptographic enforcement of who may trigger a `group-key` distribution. An admin (or an attacker who manipulates the role client-side, e.g. by directly manipulating the local state before a restart) could theoretically add/remove members arbitrarily, without other members being able to verify this cryptographically — they trust the `group-key` message because it arrives over an authenticated 1:1 session with the (supposed) admin, not because a role is cryptographically proven. |
| **Severity** | Medium (already requires a group membership, no foreign attack, but a malicious/compromised admin has more power than the UI suggests) |
| **Concrete improvement** | Sign role changes/member changes (with the admin's identity key) instead of only distributing them over the encrypted channel — would be co-solved anyway in an MLS migration (see section 7). |

### 14. MITM during device pairing

| | |
|---|---|
| **Protected assets** | Identity binding of a new device |
| **Attack vector** | An attacker intercepts the communication between two devices of the same user during pairing |
| **Current protection** | **Not applicable — no device-pairing flow exists** (see section 0). There is therefore currently also no MITM attack vector AGAINST pairing, because nothing is paired. |
| **Remaining risk** | As soon as a pairing feature is built (recommendation see section 6/8), it MUST be designed MITM-resistant from the start (e.g. through a confirmation derived from a shared channel — a QR code directly between the devices — NOT only over the already potentially compromised relay). |
| **Severity** | Not assessable (the feature does not exist) — noted as a **design requirement for phase 14**. |
| **Concrete improvement** | See section 8, a draft of a QR-based provisioning protocol with channel binding. |

---

## 2. Cryptographic primitive analysis

Each line: input → output → encoding → domain separation → KDF context →
key lifetime → nonce lifetime → error behavior. Source:
`client/src/crypto/primitives.ts`, `ratchet.ts`, `pq.ts`, `vault.ts`,
`safety.ts`, `padding.ts`.

### X25519 (`@noble/curves/ed25519`, function `x25519`)
- **Input:** a 32-byte private key (`x25519.utils.randomPrivateKey()`, from `crypto.getRandomValues`), the counterpart's 32-byte public key.
- **Output:** a 32-byte shared secret (`x25519.getSharedSecret`).
- **Encoding:** raw bytes, Base64 for transport/storage (`b64.enc`/`.dec`).
- **Domain separation:** none needed at the X25519 level itself — it happens one level up in the HKDF info string (see below).
- **Error behavior (checked in this audit):** `@noble/curves`'s `scalarMult` explicitly throws `'invalid private or public key received'` when the result is a low-order point (incl. zero) — RFC-7748-compliant validation, verified by reading `node_modules/@noble/curves/esm/abstract/montgomery.js` and by a regression test (`handshake.test.ts`: "a manipulated low-order DH public key is rejected by X25519"). **No finding** — implemented correctly.
- **Key lifetime:** identity key: permanent (until account re-creation). Prekey: permanent, but rotatable (no automatic rotation implemented — see the finding below). One-time prekey: single-use, deleted server-side after consumption. Ratchet DH keys: per epoch (each DH-ratchet step generates a new one).

### ML-KEM-768 (`@noble/post-quantum/ml-kem.js`)
- **Input:** `ml_kem768.keygen()` returns `{secretKey, publicKey}`; `encapsulate(publicKey)` returns `{cipherText, sharedSecret}`; `decapsulate(cipherText, secretKey)` returns `sharedSecret`.
- **Output:** a 32-byte shared secret (FIPS-203-compliant).
- **Error behavior (checked):** ML-KEM uses implicit rejection (the Fujisaki-Okamoto transform) — a manipulated `cipherText` does NOT lead to an exception, but to a deterministically wrong but valid-looking shared secret. Verified by test (`handshake.test.ts`: "a manipulated PQ ciphertext leads to an implicit KEM reject"). This is **correct, specification-compliant behavior** (protection against padding-oracle-like attacks), not a bug — importantly, the higher protocol layer (Double Ratchet, AES-GCM tag check) still detects the wrong secret safely as a failure, which is the case (the resulting first ratchet message then fails the AES-GCM tag check).
- **Domain separation:** the ML-KEM shared secret is given together with the X25519 DH outputs into ONE HKDF call (`concat(...parts)` incl. `pqSecret`), with a domain-separated info string — no separate HKDF step for PQ alone. That is the established "hybrid" approach (like Signal's PQXDH), correctly implemented.
- **Key lifetime:** the PQ prekey is, like the classical prekey, permanent without automatic rotation (the same rotation finding as above).

### Ed25519 (`@noble/curves/ed25519`)
- **Purpose:** exclusively for relay authentication (challenge-response: the server sends a nonce, the client signs with `edPriv`, the server verifies with `edPub`) — NOT for message signatures or X3DH identity binding (that runs via X25519 DH, classically for X3DH).
- **Input/output:** `ed25519.sign(msg, priv)` → a 64-byte signature; `ed25519.verify(sig, msg, pub)` → boolean.
- **Nonce:** server-side `crypto.randomBytes(32)` per connection, used once (`meta.nonce = null` set after verification) — no replay of an old challenge possible, since the state is deleted after consumption. **Correct.**
- **Error behavior:** `ed25519.verify` is wrapped in a `try/catch` (`server/src/index.js`, case `'proof'`) — a malformed signature/nonce leads to `ok = false`, not to an uncaught exception. **Correct.**

### AES-256-GCM (WebCrypto `crypto.subtle`)
- **Nonce/IV:** 12 bytes, `rand(12)` = `crypto.getRandomValues` — freshly generated per encryption operation, prepended to the ciphertext (`concat(iv, ct)`), separated again on decryption (`data.subarray(0, 12)`).
- **Nonce reuse risk:** with random 96-bit nonces and the number of encryption operations realistically arising in an app lifetime, a collision per the birthday paradox (√(2^96) ≈ 2^48 operations for a 50 % collision probability) is practically excluded — **no finding**, standard procedure, identical to Signal.
- **AAD:** the ratchet header (`JSON.stringify(header)`) is passed along as Additional Authenticated Data — binds header integrity to the ciphertext without encrypting the header itself (it must stay readable to decrypt at all). **Correctly constructed**, but the use of `JSON.stringify` instead of a canonical, fixed byte layout is a fragility note (no current bug, since the encoder/decoder are consistent in this codebase, but a theoretical risk for future cross-platform interop, if e.g. a native/Rust implementation ever had to serialize the same headers independently — the JSON key order is deterministic in this codebase, but not enforced by a standard). **Recommendation (P3):** switch to a fixed byte layout (e.g. `dh(32) || pn(4) || n(4)`) as soon as a second independent implementation (e.g. native mobile) is planned.
- **Key lifetime:** message keys (Double Ratchet) are single-use (deleted from the `skipped` map after use, or never re-derived). The vault master key is long-lived (the session duration), the vault KEK is only held transiently during unlock.

### HKDF-SHA256 (`@noble/hashes/hkdf`)
- **Info strings used (domain separation), full list:**
  - `RenkerVault-DoubleRatchet-RK` (the root-key chain in the ratchet)
  - `RenkerVault-X3DH-full-PQ-hybrid` (handshake WITH a one-time prekey)
  - `RenkerVault-X3DH-lite-PQ-hybrid` (handshake WITHOUT a one-time prekey)
  - `RenkerVault-Vault-MAC` (the HMAC key for vault integrity, derived from the master key)
  - `RenkerVault-SealedSender-Tag` (the session tag for sealed sender)
  - **Checked:** all five strings are literally pairwise distinct — no collision, no reuse of one context for two different purposes. **No finding.**
- **A missing element:** the symmetric-ratchet step (`kdfCk`) uses **HMAC directly**, not HKDF (`hmacSha256(ck, [1])`/`hmacSha256(ck, [2])`) — that is **correct and specification-compliant** (the official Double-Ratchet specification defines `KDF_CK` explicitly as HMAC with two constant bytes, not as HKDF) — no finding, only documented for completeness so it is not mistaken for an inconsistency.

### Argon2id (`hash-wasm`)
- **Parameters:** `iterations: 4, memorySizeKiB: 65536 (64 MiB), parallelism: 1, hashLength: 32`. In the lower but still accepted range of the OWASP recommendation (the OWASP Cheat Sheet recommends, depending on the version, e.g. m=19MiB/t=2 as a strict minimum up to m=... for higher security — 64 MiB/t=4 is above the minimum, but a deliberate trade-off in favor of the unlock latency on weaker hardware, already documented in SECURITY.md). **No new finding**, the parameters are defensible, not optimal for high-security scenarios.
- **Salt:** 16 bytes `rand(16)` per vault, correctly one-time and random. The duress PIN uses a SEPARATE salt (`file.duress.salt`) — correct, prevents cross-context derivation.
- **Error behavior:** no explicit try/catch around `argon2id()` itself in `deriveKey()` — an internal WASM error (e.g. OOM at 64 MiB on very limited devices) would propagate as an uncaught exception out of `unlockVault`/`createVault`. **A small finding (P3):** no specific error handling for Argon2id execution errors (separate from "wrong password"), the UI would presumably show a generic error instead of a meaningful message ("the device has not enough memory for unlocking").

### Double Ratchet — see the separate, detailed section 3 below.

### Prekeys / one-time prekeys
- **Generation:** `topUpOneTimePrekeys()` generates new OTPKs as soon as the local stock falls below `OTPK_LOW_WATERMARK` (15), up to `OTPK_TARGET` (25), a maximum of `OTPK_MAX_STORE` (60) held locally.
- **Server-side consumption:** `lookup` with `forHandshake=true` removes exactly one OTPK immediately from `dev.otpks` — **before** the completion of the actual handshake (a finding already documented in the last audit, FINDING-011, P3: exhaustion through lookups without a handshake completion possible).
- **No expiry for prekeys** (neither the signed prekey nor the OTPK) — there is no automatic rotation of the identity's own `prekeyPub`/`pqPrekeyPub`. In Signal, the signed prekey rotates periodically (e.g. weekly) and is published signed. RenkerVault generates the prekey/PQ prekey **once at account creation** and never rotates them automatically — a finding not addressed in the last audit. **A new finding (P2):** the missing periodic prekey rotation extends the window in which a compromise of the (long-lived) prekey private key retroactively weakens the forward secrecy of the first-contact handshake with EVERY future contact, until the account is re-created.
- **No signature of the signed prekey by the identity key** — classical X3DH prescribes that the signed prekey is signed by the identity key (`Sig(IK, SPK)`), so that the recipient can check that the prekey actually stems from the claimed identity owner BEFORE using it for a handshake. In RenkerVault there is no such signature — the prekey is simply delivered to the initiator by the relay via `lookup()` and used unchecked. Since the security ultimately comes from the X3DH DH computation itself (a wrong prekey would lead to a shared secret the real recipient does not know, i.e. a failure of the first message), it is **not a direct confidentiality breach**, but an explicit cryptographic binding "this prekey demonstrably belongs to this identity", which the client could rely on WITHOUT risking a whole message first, is missing. **A finding (P2):** the prekey signature is missing (a standard X3DH element).

### Session establishment (X3DH hybrid)
See the cryptographic analysis above (HKDF domain separation) and section 0
(downgrade detection, FINDING-003). Additionally checked in this audit:
**no key-confirmation step** separate from the first ratchet message
— that is functionally identical to Signal's own approach (the first
AEAD-encrypted message itself serves as confirmation, since its
auth tag only checks with a correctly derived `sk`), so **no finding**, only
explicitly confirmed for completeness.

### Device authentication
Ed25519 challenge-response on connection setup to the relay (see above).
**No finding** in the challenge-response mechanic itself — the findings lie
at the level of "who may count as a device" (section 0/1.4), not in the
authentication primitive.

### Safety numbers (`crypto/safety.ts`)
- **Construction:** 512 rounds of SHA-256 over the sorted-concatenated
  X25519 public keys of both parties, with a fixed domain prefix
  (`RenkerVault-SafetyNumber-v1`).
- **A finding (P3, new in this audit):** 512 SHA-256 rounds is an
  unusual iteration count not oriented at a standard (Signal's
  own procedure uses 5200 rounds of SHA-512 per "version", with
  additional inclusion of stable user IDs, not only the public keys).
  This is **not a security breach** (safety numbers need not be
  brute-force-resistant — they are meant for visual comparison by
  humans, not as a secret value), but the construction
  matches no established, externally reviewed procedure, which would stand out
  in an external audit. **Recommendation (P3):** switch to a
  documented, established procedure or explicitly
  justify why the own construction is sufficient (currently not
  justified).
- Binds only to **static identity keys**, not to devices — with
  multi-device (once implemented), the safety number would either have to capture
  all devices of an identity or there would have to be separate
  per-device fingerprints (as in Signal), otherwise a constant
  safety number reveals nothing about a newly added
  device. **Currently not relevant**, since there is no multi-device usage over
  the UI (see section 0) — but a design point for phase 6/14.

### Group encryption
See section 7 (group cryptography) below — already documented in the last audit
as FINDING-010 (no forward secrecy per message
within an epoch, no sender authentication). This audit
deepens that in section 7 with an explicit assessment of an
MLS migration, as required in phase 4 of the task.

### Key rotation
- **Ratchet:** automatic on every reply round trip (inherent in the Double-Ratchet design). Correct.
- **Group epoch key:** on every member change, verified correctly (see the last audit).
- **Identity/prekey keys:** **no rotation** — see the finding above (P2).
- **Vault KEK/master key:** rotation on passphrase change not checked — **an open question for phase 5:** is there a "change passphrase" function at all? (Grep result: no `changePassphrase` or similar found — **a finding (P2): there is no way to change the vault passphrase afterwards** without recreating the vault completely and losing all data (`destroyVault` + `createVault`). This is both a usability and a security finding: users who suspect a compromised passphrase have no way to rotate only the passphrase without losing the entire identity (incl. all existing ratchet sessions with contacts!).

### Key storage
See section 5.

### Nonce generation
Consistently `crypto.getRandomValues()` (AES-GCM IVs, Argon2 salts,
Ed25519 server nonces, `deviceId`/`msgId`/`userId` generation). **No
own PRNG, no finding.**

### Replay protection
- **Ratchet level:** correct after the last audit (the state is committed only after
  a successful auth, a replay of an already-processed or
  already-skipped message key fails safely, see
  the FINDING-001 regression tests).
- **Relay-auth level:** correct (the nonce is one-time, deleted after verification).
- **Envelope level (newly checked in this audit):** there is **no
  check at the envelope level itself against exact re-delivery
  of the same `msgId`** beyond what the ratchet already catches
  via the message counter. For `kind: 'reaction'`/`'edit'`/`'delete'`
  (which reference a `targetMsgId`), the client does not check whether a
  particular `targetMsgId` has already been edited/deleted before
  it applies the operation again — a relay that duplicates an `edit`
  message would harmlessly apply the same (idempotent) edit
  twice. **No security risk** (idempotent operations), only checked for
  completeness and assessed as unproblematic.

---

## 3. Double Ratchet — in-depth state-machine analysis (phase 3)

**Assessment of the core question "migration to an established library vs.
hardening the existing implementation":**

As already correctly documented in README.md: there is currently **no
maintained, audited browser-JavaScript implementation** of the
Signal protocol (`libsignal-protocol-javascript` is archived;
`@signalapp/libsignal-client` is a native Node module, not a
browser/WebView-compatible library without additional compilation/FFI
work). A migration to an "established library" is for the
browser/web part of this project **currently not directly possible**, without
either (a) including `@signalapp/libsignal-client` via Tauri-Rust FFI only for the
desktop variant (would leave the web/Android variant still
with the own composition — inconsistent security
levels between platforms) or (b) switching to a completely new,
cross-platform base (a considerably larger rebuild).

**Decision of this audit (consistent with the assessment in the last
pass):** **harden and test** the existing composition instead of
repairing "by feel" or migrating blindly. Rationale:

1. The primitives themselves (`@noble/curves`, `@noble/post-quantum`,
   WebCrypto AES-GCM, HKDF) are externally audited, established
   libraries — only the **composition** (how the primitives are assembled into the
   Double-Ratchet protocol) is project-own.
2. The only **critical** bug found so far in this composition
   (state commit before the auth check, FINDING-001) is fixed and covered with 20
   targeted regression tests that map exactly the scenarios required in phase 3 of this
   task (out-of-order, packet loss,
   replay, concurrent sends, state-rollback attempts, session restore).
3. A migration to a native library ONLY for desktop would create a
   **downgrade vector** (web/Android stay with the own
   implementation; an attacker could deliberately pick web clients as a
   weaker target) — that contradicts phase 2, point 5 of this
   task ("prevent a downgrade to the old protocol").

**It nevertheless stands firm:** this composition is and remains a
**high-risk component in the sense of this audit task**, until an
**external** cryptography audit has taken place. Internal tests increase
the confidence, but do not replace an external review — this is
repeated and clearly marked in SECURITY.md, THREAT_MODEL.md, and here,
not just mentioned once in passing.

### Checked scenarios and their current status

| Scenario | Status | Test coverage |
|---|---|---|
| A→B, B→A, A→B→A, many messages | ✅ Correct | `ratchet.test.ts`, describe "basic flow" (incl. a 1000-message test, 200-round alternation) |
| Out-of-order (1,3,2 or 1,4,2,3) | ✅ Correct | `ratchet.test.ts`, describe "out-of-order delivery" |
| Packet loss (message 2 lost, 1+3+4 received) | ✅ Correct | Ibid., "one lost message" |
| Replay (the same message multiple times) | ✅ Correct since the FINDING-001 fix — fails safely, does not corrupt the state | Describe "replay and tamper protection" (6 tests) |
| Concurrent sends (A and B "simultaneously") | ✅ Correct | Describe "simultaneous sending / DH ratchet" |
| State corruption (damaged state, damaged keys, damaged headers) | ✅ Tested for header/ciphertext manipulation (tamper tests). **Not tested:** a directly corrupted *persisted* snapshot (`RatchetSnapshot` with inconsistent fields, e.g. `nr` > actual chain progress) — see the new finding below. |
| Crash recovery (a crash between the state update and persistence) | ⚠️ **Not specifically tested.** See the analysis below. |
| Compromise scenarios (old/new state compromised, resumption) | ⚠️ Partly covered by the forward-secrecy properties of the ratchet (each DH-ratchet step makes old chain keys irrelevant for new messages), but no explicit test that compares a compromised OLD snapshot against a current snapshot to demonstrate post-compromise security after a ratchet step. |
| Session termination / restart | ✅ Tested (snapshot → fromSnapshot → further message exchange) | Describe "session restore / device restart" |
| Device changes | See section 0/1.4 — not applicable at the ratchet level itself (the ratchet is per 1:1 session, not per device) |

### New findings in this pass (ratchet-specific)

**Finding RATCHET-A (P2): no protection against persisting an
inconsistent snapshot through a process crash.** `saveRealSessions`
(in `App.tsx`, called after every send/receive) writes the
ratchet snapshot as part of the entire vault state via `saveVault()`.
Between a successful `ratchet.decrypt()`/`.encrypt()` operation
(which has already changed the in-memory state) and the actual
`saveVault()` call there is a time span in which a process crash
(power failure, kill, crash) would lead to the message already
shown/sent in the UI NOT being reflected in the persisted snapshot.
For a sent message (`encrypt()`): the
state is already advanced (`ns` increased), but the old, not
yet persisted `ns` number is used again after a restart —
that means a ciphertext already sent to the relay would have used a
message key that would be derived **again** from the
same (unadvanced) chain key on the NEXT restart-send, if the
old, in-memory already-advanced state was not persisted,
but the client restarts from the last SAVED (older) snapshot. **This is a potential
message-key-reuse problem on crash recovery, not tested, not hardened.** Recommendation for
phase 14: enforce `saveVault()` synchronously/atomically directly after EVERY
state-changing ratchet operation (not bundled/delayed)
and write a regression test that reproduces a simulated crash between
`encrypt()` and `saveVault()` (save the state snapshot before the "crash",
then check whether a renewed send would produce the same message key
as before the crash — if so: the bug is confirmed and to be fixed).

**Finding RATCHET-B (P3): `fromSnapshot()` does not validate the input.**
A corrupt/manipulated `RatchetSnapshot` (e.g. from a
manipulated but not yet HMAC-checked intermediate state,
or a programming error elsewhere) is adopted
uncritically — `nr`/`ns`/`pn` could e.g. contain negative or nonsensically large
values, without `fromSnapshot()` rejecting it. Since the
snapshot is part of the HMAC-protected vault content, an external
manipulation is already covered by the vault integrity check — this
finding concerns only **internal consistency** (a bug elsewhere in the
code that accidentally produces an inconsistent snapshot would
not stand out). Recommendation: add simple sanity checks (`nr >= 0`, `ns >= 0`,
`pn >= 0`) in `fromSnapshot()`, with a test.

---

## 4. Group cryptography (phase 4 — as-is state documented exactly)

**How group keys arise:** `newGroupEpochKey()` (`ratchet.ts`) —
`rand(32)`, a random 256-bit key, independent of any
member key. No KDF, no derivation from identity keys —
a pure random value per epoch.

**How they are distributed:** `distributeGroupKey()` (`App.tsx`) sends the
current epoch key **individually, pairwise, over the existing 1:1 ratchet
session** to each member (a `kind: 'group-key'` envelope, encrypted
with that member's respective individual Double-Ratchet key). No broadcast
mechanism, no separate group KEM.

**How epochs work:** `newGroupEpoch(chatId, prevEpoch)` increases
the epoch counter by 1 and generates a new random key.
`applyGroupKey()` at the recipient adopts the key+epoch uncritically,
as soon as a `group-key` message arrives over an authenticated 1:1 session —
**no check whether the new epoch is actually >
the previous epoch** (see the new finding below).

**What happens on join:** `handleAddMemberReal` → `rotateRealGroup` →
a new epoch, a new key, distribution to ALL (old + new)
members. Correct: the new key guarantees that the new
member cannot read OLD messages (sent before its join),
since it never receives the old epoch key — **forward secrecy relative
to new members exists.**

**What happens on leave/removal:** analogous, `handleRemoveMemberReal` →
`rotateRealGroup` with the filtered member list. Verified
correctly in the last audit — a removed member does not get the new
key and can consequently not read new messages
(**post-compromise security at the epoch boundary exists**).

**What happens on device removal:** not applicable / non-existent,
since multi-device (see section 0) is not reachable client-side —
"device removal" within a group would currently behave like a
normal member removal (the entire account, not a
single device of it, is removed from the member list).

**Forward secrecy:** ❌ **Not within an epoch.** All messages
of an epoch use the same static AES-256-GCM key
(`encryptGroup`: `aesGcmEncrypt(g.key, padToTier(plaintext))` — the same
`g.key` for every message of the epoch, only the random IV varies).
An epoch key once compromised decrypts **every** message
of that epoch — including ones already weeks old. Across epochs there is
forward secrecy (old epoch keys are not derived from new ones,
are independent random values), but NOT at the message level within
the same epoch.

**Post-compromise security:** ✅ At the epoch boundary (after the next
rotation, a previously compromised key is useless), ❌ not immediately
(an attacker with a compromised current epoch key reads
EVERY further message until the app logic triggers a rotation — there is
no automatic, time-based rotation trigger, only a
member-change-based one).

**Which messages can be decrypted with a compromised epoch key:** all messages of that one epoch — forward AND backward
in time, up to the next member change.

**New finding GROUP-A (P1, discovered in this audit):** `applyGroupKey()`
does **not** check whether the incoming `epoch` number is actually greater than
the last known one:

```ts
applyGroupKey(chatId: string, keyB64: string, epoch: number): string {
  const key = b64.dec(keyB64);
  this.groupKeys.set(chatId, { key, epoch }); // no comparison with the previous epoch!
  return groupFingerprint(key, epoch);
}
```

A malicious (still active, not necessarily removed)
group member — or an attacker who has compromised a 1:1 session with a
group member — could re-deliver a `group-key` message
with an **older** epoch number (a replay of a
previously legitimately sent `group-key` message). The receiving
client would fall back without complaint to the older, possibly already-known-as-compromised
key — an
**epoch-rollback attack** that directly undermines the post-compromise-security property
of the group rotation (the core promise "after
removal/rotation the old key is useless" then no longer holds
if the old key can be reactivated via replay). This is a
concrete example of exactly what phase 4 of this task asks
("prevent old epoch replays") — **found here.** Fix for
phase 14: `applyGroupKey` must reject `epoch <= this.groupKeys.get(chatId)?.epoch`
(a monotonic check), with a regression test.

**Assessment of an MLS migration:** MLS (RFC 9420) would provide forward secrecy per
message (through a TreeKEM ratchet structure instead of a single
static epoch key) and cryptographically verifiable
membership/role changes — that would structurally solve FINDING-010 (missing
FS per message) and the sender-authentication finding from section
1.6. **Not directly integrable for the current architecture:**
there is no mature JavaScript-MLS implementation suitable for browser/WebView with a comparable maturity to the
X3DH/ratchet primitives of this project (OpenMLS is a Rust library,
would need WASM compilation or Tauri FFI — a similar restriction as
with libsignal). **Recommendation for phase 14 (short-term, without MLS):**
1. Epoch-rollback protection (GROUP-A) — small, critical, immediately doable.
2. Time-based or message-count-based automatic epoch rotation
   in addition to the member-change-based one (shortens the
   compromise window within an epoch, but does not
   structurally solve the FS problem).
3. A documented, long-term recommendation: evaluate an MLS migration,
   as soon as a browser-suitable implementation matures, or when the
   Tauri desktop variant becomes the primary platform (there,
   OpenMLS via Rust FFI would be realistic).

---

## 5. Local vault hardening (phase 5 — deepened)

Already addressed in the last audit: Argon2id parameters, salt, MAC-before-
decrypt order, master-key zeroization, secure-delete attempt
(FINDING-008/009). **New points from this pass:**

- **Atomic writes:** `localStorage.setItem()` is atomic per call at the
  API level (no partially written value visible from outside), but
  the application itself does not make MULTIPLE `setItem`-like steps
  as one transaction (see RATCHET-A above — ratchet-state progress
  and `saveVault()` are temporally separated). **Assessed in section 3.**
- **Backup restore:** there is no explicit export/backup/restore
  mechanism in the app (no "export vault" button found).
  That conversely means: users who lose their device WITHOUT
  a system backup existing lose their entire chat history
  AND their identity irrecoverably — a
  usability/resilience gap, but not a security problem in the narrower
  sense (on the contrary: no backup mechanism also means no
  additional attack surface through an export path).
- **Windows DPAPI, macOS Keychain, Linux Secret Service:** DPAPI is
  implemented (Windows). The macOS/Linux equivalents are still **not
  implemented** (already documented). This audit assesses that again
  as a sensible P2/P3 extension for phase 14, not a blocker.
- **CSP (Tauri):** `tauri.conf.json` has `"csp": null` — **a finding (P1, new
  in this audit):** a `null` CSP means that Tauri's built-in
  CSP protection for the WebView is **disabled**. Tauri explicitly
  recommends setting a CSP to limit XSS impact
  (in particular `script-src`, to prevent injected code from
  calling IPC commands against the Rust backend — in the current
  case especially relevant, since DPAPI IPC commands exist that could,
  on successful XSS exploitation, be abused to manipulate/extract the
  wrapped master key). **Concrete
  recommendation for phase 14:** set the CSP explicitly (e.g.
  `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`
  — no `unsafe-eval`, no external sources, since the app per README
  loads no third-party resources anyway).
- **IPC commands (Tauri):** currently only three commands
  (`dpapi_available`, `dpapi_protect`, `dpapi_unprotect`), all in
  `dpapi.rs`, all with a minimal, clearly bounded function (no
  generic filesystem or process access exposed). **No finding**
  — the IPC surface is already minimal, exactly as phase 5
  requires ("minimize IPC with secrets").
- **`capabilities/default.json`:** uses `"core:default"` — Tauri's
  default permissions. Not restricted to the three actually
  needed custom commands (no explicit
  `Capability` entry for `dpapi_*`, which in Tauri 2.x means that
  custom commands without a registered
  `Capability` entry may NOT be callable, unless otherwise
  released via the plugin system — **must be verified in phase 14**,
  whether the DPAPI commands even work with the current capability
  configuration, or whether that already silently breaks untested in
  a real Tauri GUI. Already marked in the
  last audit as "not verifiable in this environment" —
  stays open).
- **Secure-memory guarantees that JavaScript CANNOT provide (explicitly,
  as required by phase 5):** no `mlock()` equivalent (memory can
  be swapped out to the swap file at any time), no guaranteed
  overwriting of object memory before garbage collection (V8 can
  copy/move objects), no control over
  compiler/JIT optimizations that could optimize away a "dead" zeroization write
  (the `Uint8Array.fill(0)` pattern from FINDING-008
  is the best-possible but not guaranteed approximation, since it is a
  visible mutation of a still-referenced object, which reduces the
  optimize-away risk but does not bring it to zero). **These
  limits are already named in SECURITY.md — this audit confirms
  that none of the previous formulations claim "secure deletion" as
  a guarantee (searched: no such exaggeration found).**

---

## 6. Device pairing — analysis of the as-is state (phase 6)

See section 0 in detail. A short version of the assessment against the
concrete check points from the task:

| Check point | Status |
|---|---|
| Identity binding | Not applicable (no pairing flow) |
| QR-code data | A safety-number QR exists (verification of existing contacts), no pairing QR |
| Challenge/response | Exists for relay auth (Ed25519), not for device pairing in the narrower sense |
| Key confirmation | Not applicable |
| MITM protection | Not applicable (see attacker #14 above) |
| Replay/expiration | Not applicable |
| Device authorization | Correctly enforced server-side (`trusted` flag, since FINDING-004/005), but without a reachable "add a new device" flow, effectively only reachable via the (not intended) vault-file copy |
| Device revocation | Works (`revoke-device`, trust-checked server-side) |
| New device trust | Correctly NOT automatic server-side (`isFirstDevice` bootstrap excepted) |
| Server enforcement | ✅ Already present (last audit) — all security-critical permissions (`approve-device`, `revoke-device`, live delivery, `lookup()`) are checked server-side, not only client-side. Already fulfills the explicit requirement "A newly registered device may never count as trusted solely on the basis of a client-side convention." |

**Recommendation for phase 14 (see also section 8 for a concrete
protocol draft):** before the regression tests required in this task
("unauthorized device", "expired pairing", "replayed
pairing", "wrong device", "modified QR data", "revoked device",
"compromised session") can sensibly be written, the
pairing feature itself must exist. The server-side building blocks
(`revoke-device`, trust enforcement) are already present and tested;
what is missing is the client flow that attaches a second device WITH ITS OWN
keys (not by copying the identity!) to an existing account,
and thereby binds the new device `edPub` cryptographically to the
existing identity.

---

## 7. Relay server (phase 7 — additions to the last audit)

Already addressed: auth flow, rate limits, trust enforcement, bounded
storage (FINDING-004 to 007, 011, 012). Newly checked in this pass:

- **Origin validation:** the `WebSocketServer` (`ws` library) currently checks
  **no** `Origin` header on connection setup (`wss.on('connection', ...)`
  accepts every connection independent of the origin header). For a
  desktop/mobile app that is at its core unproblematic (no
  same-origin context as in the browser), but for the **web client** in the
  browser it means: any arbitrary website could theoretically, from
  a victim's browser, set up a WebSocket connection to the same
  relay (WebSocket is NOT restricted by CORS/SOP like
  `fetch`/XHR). That alone is not yet a breach (the attacker would
  still need valid credentials/signatures for an account to do anything
  meaningful), but it deprives the server of a free, additional
  defense layer against browser-based command-and-control-like usage
  of the relay by malicious third-party sites (e.g.
  mass anonymous trying of `lookup` requests for
  user enumeration from any website, in the name of the
  browser victim, but without their consent). **A finding (P2, new):**
  the missing origin check for browser clients.
- **User enumeration:** `lookup` returns `found: true/false` immediately
  — an attacker can, by systematically trying
  `userId` values (`RV-XXXX-XXXX`, 32 bits effective entropy), determine
  which accounts exist. Rate limiting exists (`OTPK_LOOKUP_RATE_LIMIT`
  for `forHandshake:true` lookups), but **normal** lookups
  (`forHandshake:false`, e.g. pure name/presence queries) are NOT
  separately rate-limited — only implicitly via the generic
  per-socket message limit (30/s). At 30 lookups/second the
  32-bit `userId` space (4.3 billion) could not be searched in a practical
  time from a single socket (~4.5 years at 30/s), but
  with several parallel connections (limited only by `MAX_CONNS_PER_IP=20`,
  not globally) considerably accelerable. **A finding (P2, new):**
  no dedicated rate limit for normal (non-handshake) lookups,
  user enumeration thereby accelerable.
- **Timing leakage:** `guard()`/`recordAuthFail()` run structurally the same for
  existing and non-existing `userId`s (`getUser()` transparently creates an
  empty entry on demand) —
  **no timing difference found between "account does not exist" and "account
  exists, but a wrong signature"**, that is positive (prevents an
  account-existence timing oracle over the auth path).
- **Error messages:** all error responses (`{type:'error', error: '...'}`)
  use short, generic codes (`bad-hello`, `key-mismatch`,
  `not-trusted`, `rate-limited` etc.) without internal details (stack traces,
  internal IDs) — **no finding**, clean.
- **Message size limits:** `MAX_MSG_BYTES = 2 MiB` via the `WebSocketServer`
  `maxPayload` option — enforced by the `ws` library itself
  (the connection is closed server-side on exceeding), **correct**.
- **Connection handling:** `AUTH_TIMEOUT_MS` (15s) automatically closes unauthenticated
  connections — **correct**, prevents Slowloris-like
  holding open of unauthenticated sockets.

---

## 8. Metadata privacy (phase 8 — reference)

Fully documented already in [docs/METADATA.md](docs/METADATA.md) (field-by-field
analysis) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (what relay/Tor/
cover-traffic/PQ protect). No new findings in this
pass beyond those already named there (the biggest open point:
`replyTo.preview` and `fromName` still lie in the plaintext envelope,
not in the encrypted payload — already recorded as a prioritized recommendation
in METADATA.md).

---

## 9. Draft: a QR-based device-provisioning protocol (for phase 14)

Since device pairing as a feature is missing (section 0/6), here a concrete
draft, oriented at Signal's device linking, that on implementation in
phase 14 is MITM-resistant and gets by without a key exchange over the
(potentially malicious) relay:

1. The **primary device** (already logged in) shows a QR code with: its
   own `userId`, a fresh, short-lived X25519 ephemeral public key,
   and a random 128-bit provisioning nonce.
2. The **new device** scans the QR code (channel binding: the QR code itself
   is the trusted out-of-band channel, no relay involved),
   generates its OWN full key bundle locally (NOT
   copying the primary device's identity — every device keeps its own
   private keys, as in Signal), and encrypts its new
   `edPub`/`xPub`/device metadata with a shared secret derived from the scanned
   ephemeral key + its own ephemeral key
   (ECDH), additionally signed with its own new `edPriv`.
3. This encrypted provisioning message is sent over the relay to
   the primary device (the relay sees only ciphertext, as with
   any other message).
4. The **primary device** decrypts, shows the user the device metadata
   (name, type) for confirmation, AND a short confirmation code
   derived from the ephemeral shared secret — which MUST match an
   identical code shown on the NEW device (analogous to
   Bluetooth pairing codes). Only after this double confirmation
   (the user confirms on BOTH devices) does the primary device send
   `approve-device` to the relay.
5. **Expiration:** the provisioning nonce/the QR code is only valid for 2 minutes;
   expired provisioning attempts are discarded by the primary device
   (a client-side check suffices here, since an expired
   attempt never leads to an `approve-device` anyway).

With this, MITM during pairing would be structurally excluded (the
QR-code scan itself is the trust anchor, not the relay), and
`approve-device` would only be triggered after a REAL, doubly confirmed
device identification — no longer through a mere click on
a device list that a user could misinterpret on inattention
(the section-1.4 residual risk).

---

## 10. Prioritized findings overview (a starting point for phase 14)

| ID | Severity | Short description | New in this audit? |
|---|---|---|---|
| GROUP-A | **P1** | Group epoch rollback: `applyGroupKey` does not check the epoch monotonically, a replay of an old `group-key` message reactivates an old (potentially compromised) key | ✅ Yes |
| VAULT-CSP | **P1** | Tauri CSP is `null` — WebView XSS protection disabled, especially risky because of the present DPAPI IPC commands | ✅ Yes |
| RATCHET-A | **P2** | No protection against inconsistent ratchet-state persistence on a process crash between the state update and `saveVault()` | ✅ Yes |
| PREKEY-ROTATE | **P2** | No automatic rotation of the identity prekey/PQ prekey | ✅ Yes |
| PREKEY-SIG | **P2** | The signed prekey is not signed by the identity key (a classical X3DH element missing) | ✅ Yes |
| PASSPHRASE-ROTATE | **P2** | No way to change the vault passphrase without losing the entire identity | ✅ Yes |
| RELAY-ORIGIN | **P2** | No `Origin` header check, WebSocket is not CORS-restricted | ✅ Yes |
| RELAY-ENUM | **P2** | No dedicated rate limit for normal (non-handshake) `lookup` calls — user enumeration accelerable | ✅ Yes |
| STORAGE-ROLLBACK | **P2** | No generation counter in the vault format — a rollback to an older but valid vault version undetected | ✅ Yes |
| RATCHET-B | **P3** | `fromSnapshot()` does not validate input values (sanity checks missing) | ✅ Yes |
| SAFETY-NUM | **P3** | The safety-number construction (512×SHA-256) follows no established standard | ✅ Yes |
| AAD-ENCODING | **P3** | The ratchet AAD uses `JSON.stringify` instead of a fixed byte layout (fragility on future cross-platform interop) | ✅ Yes |
| ARGON2-ERR | **P3** | No specific error handling for Argon2id execution errors (separate from "wrong password") | ✅ Yes |
| DEVICE-PAIRING | **P2** (a feature gap, not a bug) | No client flow for "add a new device to an existing account" — makes phase 6 moot until built | ✅ Yes |
| CI-MISSING | **P2** | No CI pipeline (`.github/workflows` does not exist) — no automated `npm audit`/test/build check on PRs | ✅ Yes |
| SBOM-MISSING | **P3** | No SBOM, no artifact attestation, no code signature (partly already documented in SECURITY.md) | Partly known, deepened here |
| FINDING-001 to 012 | (see docs/FINDINGS.md) | All already fixed or documented in the last audit | No (reference) |

**P0 (critical):** in this pass **no new P0 findings** — the
two P0 bugs from the last audit (ratchet-state corruption,
relay-trust bypass) are already fixed and tested. That is a
positive result, no reason for negligence — GROUP-A and
VAULT-CSP are P1 and should be treated as a priority.

---

## Summary for phase 14

Priority for the implementation phase, as required by the task:

- **P0:** none open.
- **P1:** GROUP-A (epoch-rollback protection), VAULT-CSP (set the Tauri CSP).
- **P2:** RATCHET-A, PREKEY-ROTATE, PREKEY-SIG, PASSPHRASE-ROTATE,
  RELAY-ORIGIN, RELAY-ENUM, STORAGE-ROLLBACK, DEVICE-PAIRING (feature),
  CI-MISSING.
- **P3:** RATCHET-B, SAFETY-NUM, AAD-ENCODING, ARGON2-ERR, SBOM-MISSING.
- **P4 (developer experience):** CI-pipeline extension beyond pure
  security checks, fuzzing infrastructure (phase 11), SBOM tooling.

No code was changed in this phase. Implementation follows in
phase 14 after feedback/approval of this analysis.
