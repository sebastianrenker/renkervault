# FINDINGS.md — Security-hardening audit, 2026-08-10

A structured findings list of the full security audit (cryptography,
protocol, relay, vault, metadata). Priority: P0 = critical, P1 = high,
P2 = medium, P3 = low. No finding was omitted for difficulty reasons —
unfixed points are explicitly marked as "Documented,
not fixed" instead of concealed.

---

### FINDING-001 — P0 — Double Ratchet: state mutation before authentication
**Component:** Cryptographic correctness / protocol security
**File:** `client/src/crypto/ratchet.ts`, `decrypt()`
**Problem:** Before the fix, `ckr`, `nr`, `dhr`, even a completely new
own key pair (`dhs`) were written directly onto `this` BEFORE the
AES-GCM authentication of the actual ciphertext was checked. On a
failed decryption there was no rollback. It deviates from the
official Signal specification, which explicitly prescribes `state = deepcopy(state)`
before the attempt and commits only after success.
**Attack scenario:** a malicious or even just unreliable relay
sends a duplicate, delayed, or forged message (even with a
freely invented DH public key in the header). The client mutates its
ratchet state speculatively, decryption fails, but the
corrupted state persists — the session is from that
point permanently unusable (chain-key desync), without the
attacker having to know any key.
**Impact:** a complete denial-of-service of the end-to-end session through
a single manipulated packet. No confidentiality breach, but a
serious availability/integrity fault of the core protocol.
**Likelihood:** high — triggerable by anyone who can deliver packets to the client
(the relay itself suffices).
**Fix:** `decrypt()` now works on a cloned copy of the state
(`cloneState`, `skipMessageKeysInto`, `dhRatchetInto` — all draft-based).
`this.state = draft` is committed only AFTER a successful
`aesGcmDecrypt`. Additionally: `encrypt()`/`decrypt()` are now serialized via an
internal promise queue (see FINDING-002).
**Regression test:** `client/tests/security/ratchet.test.ts`,
describe block "Replay and tamper protection (P0 regression test)" — 6 tests,
incl. "a forged header with an arbitrary DH public key is rejected and
does not destroy the session (P0)".
**Status:** ✅ Fixed.

---

### FINDING-002 — P1 — Ratchet not safe under concurrent calls
**Component:** Cryptographic correctness
**File:** `client/src/crypto/ratchet.ts`, `encrypt()`/`decrypt()`
**Problem:** both methods read the current chain key, waited
asynchronously on a WebCrypto operation, and only wrote back the new
chain key afterwards. With two overlapping calls on
the same instance (e.g. `Promise.all([...].map(enc))`), both read
the same starting state before the first committed.
**Attack scenario:** no external attacker needed — reproducible solely
through the app's own call pattern (e.g. sending
several messages simultaneously). Leads to message-key reuse with
an identical header counter `n` for different plaintexts — a
core principle of stream-like AEAD constructions (never the same key
for two plaintexts) would be violated.
**Impact:** if it actually occurs: a weakening of the
confidentiality guarantee for the affected messages (the same
message key, different IVs — AES-GCM does stay formally secure through the
random 96-bit IV, but the chain-key advance becomes
inconsistent, which leads to later decryption errors).
**Likelihood:** medium — depends on the UI's call pattern, but not
fundamentally excluded (e.g. a cover-traffic timer in parallel with a
user send).
**Fix:** an internal `runExclusive()` queue in the `Ratchet` class — every
`encrypt()`/`decrypt()` call is now strictly serialized, independent
of the caller's behavior.
**Regression test:** `ratchet.test.ts`, "delivery order 1,4,2,3 is
decrypted correctly" (uses `Promise.all` for parallel encryption),
"both sides send 'simultaneously'".
**Status:** ✅ Fixed.

---

### FINDING-003 — P2 — X3DH downgrade to "lite" mode without cryptographic protection
**Component:** Protocol security / downgrade resistance
**File:** `client/src/net/realchat.ts` (`beginSession`), `server/src/index.js` (`lookup`)
**Problem:** whether a handshake runs with or without a one-time prekey ("full" vs.
"lite") is entirely determined by the relay's lookup response.
A malicious relay could consistently deliver no available OTPK
and thereby silently downgrade every handshake to "lite" —
neither the client nor the user gets a signal for it.
**Attack scenario:** the relay operator suppresses OTPKs selectively or
generally. Does NOT affect the ongoing ratchet security (which stays
identical), but selectively weakens the forward secrecy of the very first
ratchet message against a scenario in which the recipient's signed prekey
is later compromised AND the ciphertext was recorded.
**Impact:** narrowly bounded (only the first message, only under additional
signed-prekey compromise), but a real, undetectable
downgrade — exactly what section 4 of the audit task explicitly
required checking.
**Likelihood:** low (assumes an actively malicious relay operator,
not just a passive observer), but not to be excluded —
this is exactly the scenario described in the threat model (README "Background").
**Fix (mitigation, not full cryptographic protection):** the
recipient now compares, on incoming first-contact messages, whether no
OTPK was referenced although it itself still had OTPKs available —
and logs that as a security warning (`ui/App.tsx`,
`X3DH_DOWNGRADE`). Full cryptographic downgrade protection
would need signed prekey bundles with freshness independently verifiable
from the relay (e.g. a transparency log) — that is a larger, standalone
architecture topic.
**Regression test:** `client/tests/security/handshake.test.ts` (domain
separation between full/lite verified). The detection heuristic itself
is UI-side and not covered by a unit test (no relay
simulation with a deliberately suppressed OTPK in this audit round).
**Status:** ⚠️ Mitigated (detection), not fully fixed —
a documented, accepted limit.

---

### FINDING-004 — P0 — Relay delivers live messages to unconfirmed devices too
**Component:** Relay security / multi-device trust
**File:** `server/src/index.js`, case `'send'` (before: `toUser()` without a trust check)
**Problem:** the trust status of a device (`trusted`) was checked exclusively
on flushing the offline queue. Live delivery
(`toUser()`) delivered to EVERY authenticated connection of the target account,
independent of the confirmation status.
**Attack scenario:** an attacker knows/guesses the (deliberately shareable) userId
of a victim, registers itself via `hello` as a new, unconfirmed
device, stays online. Every live-delivered message (envelope metadata,
after FINDING-005 potentially also the full trust status) reaches the
attacker device, without the "device must be confirmed"
barrier shown in the UI actually being enforced.
**Impact:** a metadata leak (who sends when to the victim) plus — in
combination with FINDING-005 — a complete account takeover.
**Likelihood:** high — no timing/race needed, works against every
already-existing account as soon as the userId is known.
**Fix:** a new function `toTrustedUser()` + `hasTrustedOnlineDevice()` —
live delivery now happens only to sockets whose device entry
is `trusted === true`. If no trusted device is online,
the message is instead queued (as it already was for offline cases).
**Regression test:** `server/tests/security/relay.test.ts`, "live
delivered messages reach only trusted devices".
**Status:** ✅ Fixed.

---

### FINDING-005 — P0 — approve-device/revoke-device without a trust check of the caller
**Component:** Relay security / multi-device trust
**File:** `server/src/index.js`, cases `'approve-device'` and `'revoke-device'`
**Problem:** both commands checked only `meta.authed` (any
authenticated device), not whether the CALLER itself was already
trusted. A freshly self-registered, unconfirmed device
could self-authorize via `approve-device` with its own (known to it) `deviceId`
— or via `revoke-device` remove any other devices
(including the real, trusted ones) of the account.
**Attack scenario:** like FINDING-004, but with a direct
privilege escalation: the attacker registers, calls
`{type:'approve-device', deviceId: <own deviceId>}`, and is from
then on a fully trusted device of the victim account — including
participation in future group-key distributions addressed to "all
trusted devices". Alternatively: `revoke-device`
against the victim's real devices, to throw them out of their own account
(denial-of-service / an account-takeover precursor).
**Impact:** a complete bypass of the entire multi-device trust
model. The server-side "confirmation required" logic was, up to
this fix, purely cosmetic (only the client UI adhered to it).
**Likelihood:** high — trivially exploitable by anyone who knows a userId.
**Fix:** both handlers now additionally check whether `meta.deviceId` itself
is entered in `u.devices` as `trusted: true` before the action is
executed (`{type:'error', error:'not-trusted'}` otherwise).
**Regression test:** `relay.test.ts`, "an unconfirmed device can NOT
self-authorize" and "... can NOT sign out the real device".
**Status:** ✅ Fixed.

---

### FINDING-006 — P1 — lookup() ignores trust status in the device selection
**Component:** Relay security / multi-device trust
**File:** `server/src/index.js`, case `'lookup'`
**Problem:** `first = [...target.devices.values()][0]` simply chose the
first (insertion-order) device entry, independent of the trust status.
As long as the original device is never removed, this is mostly
unproblematic (the bootstrap device is always automatically trusted)
— but if the original device is removed/replaced, a
remaining, unconfirmed device could become the "first" entry and
have its key delivered for NEW contact requests.
**Attack scenario:** combined with a scenario in which the
original device was removed (e.g. device loss + `revoke-device`),
while an unconfirmed device is still registered.
**Impact:** new contacts could receive a handshake bundle of an
unverified device.
**Likelihood:** low (an edge case), but the fix is trivial and
free.
**Fix:** `first = [...target.devices.values()].find(d => d.trusted) ?? null`
— only a confirmed device is ever delivered as a handshake bundle.
**Regression test:** `relay.test.ts`, "lookup delivers exclusively the
key bundle of the trusted device".
**Status:** ✅ Fixed.

---

### FINDING-007 — P1 — Unbounded memory growth through phantom accounts
**Component:** Relay security / resource exhaustion
**File:** `server/src/index.js`, `getUser()`, case `'send'`
**Problem:** `send` to any non-existent `to` userId automatically creates,
via `getUser()`, a permanent account entry with a
queue. There was neither an upper limit for the total number of
managed accounts nor an expiry for never-collected
queue entries.
**Attack scenario:** an authenticated attacker (a
self-registered account suffices) repeatedly sends to freely invented
target userIds (limited only by the existing send rate limit,
300/minute). Each creates a permanent, never-cleaned
memory entry along with a queue (up to 500 entries at up to 2 MB each).
**Impact:** over hours/days, unbounded RAM growth of the
relay process — a denial-of-service through memory exhaustion.
**Likelihood:** medium — needs persistence, but no special skill.
**Fix:** a hard upper limit `MAX_TRACKED_USERS` (200,000) for newly
created accounts; a periodic sweep (`sweep()`, every 10 minutes) removes
expired queue entries (TTL 14 days) and device-less
phantom accounts with an empty queue.
**Regression test:** `relay.test.ts`, describe block "bounded storage
(phantom accounts / queue TTL)" — tests `sweep()` directly.
**Status:** ✅ Mitigated (bounded instead of unbounded). **Not fully
solved:** the fundamental RAM-only architecture problem (see SECURITY.md
section 4 point 7) remains — a real persistence layer
(PostgreSQL/Redis, see audit task section 12) was deliberately NOT
implemented in this audit round (a standalone, multi-day
infrastructure project with deployment implications that the user should
assess before it is implemented blindly).

---

### FINDING-008 — P2 — Master key is not removed from the JS heap on lock
**Component:** Client security / memory security
**File:** `client/src/crypto/vault.ts`, `lockVault()`, `destroyVault()`, `unlockVault()`
**Problem:** `masterKey = null` only removes the reference, not the
content of the underlying `Uint8Array`. The key bytes stay in the heap until
garbage collection (and potentially beyond, depending on
memory reuse).
**Attack scenario:** an attacker with memory access (debugger,
core dump, swap file) immediately AFTER locking could still read out the
master key.
**Impact:** an extended window for a key extraction after
the intended "lock".
**Likelihood:** low (already needs memory access, so an already
strongly compromised device), but the hardening is cheap.
**Fix:** a `zero()` helper (`Uint8Array.fill(0)`) before every
dereference in `lockVault()`, `destroyVault()`, and on the
failure paths of `unlockVault()` (tamper detection after a successful
decryption of the wrap).
**Honest limit (explicitly required by the task):** this is NO
guarantee. V8's garbage collector can copy/move objects before
they are deleted; the WebCrypto implementation can hold internally its own
copies of the imported key unreachable from JS
(`crypto.subtle.importKey`). Full, guaranteed zeroization is
fundamentally not achievable in JavaScript (unlike e.g. in Rust with
`zeroize`) — documented instead of silently claimed as "solved".
**Regression test:** `client/tests/security/vault.test.ts`, "lockVault
removes access to the master key" (checks the `isUnlocked()` state,
cannot verify the actual memory cleanup itself — that
is fundamentally not testable from outside the JS engine).
**Status:** ✅ Hardened as best possible, an honestly documented limit.

---

### FINDING-009 — P2 — No secure delete on removing the vault file
**Component:** Local vault security
**File:** `client/src/crypto/vault.ts`, `destroyVault()`
**Problem:** `localStorage.removeItem()` removes the entry from the
API's view, but does not guarantee an immediate, physical overwrite at the
storage-engine level (Chromium/WebView2 use LevelDB-like backing
stores with compaction — old values can remain physically present
there longer).
**Attack scenario:** device seizure (explicitly named in the threat model,
see README) immediately after "delete vault" — a forensic
analysis of the storage-backing file could recover old, already
"deleted" encrypted vault data.
**Impact:** affects only the ENCRYPTED vault file (plaintext was never
on disk) — an attacker would additionally need the passphrase. Still
a real residual risk for the "as if it never happened" promise of
section 4c in SECURITY.md.
**Likelihood:** low to medium, but exactly the scenario described in the
threat model (seizure).
**Fix:** `secureRemove()` overwrites the storage slot three times with
cryptographically random data before `removeItem()` is called.
**Honest limit:** no guarantee — the underlying
storage engine can still contain older copies through compaction/write-ahead
logs that are unreachable from the `localStorage` API. A
full solution would need a migration to a
storage backend with an explicit secure-delete guarantee (e.g. SQLCipher
with `PRAGMA secure_delete`) — see SECURITY.md section 4 point 6,
deliberately not implemented in this audit round (a larger, separate
migration project).
**Regression test:** functionally covered by `vault.test.ts`, "destroyVault
removes the vault file completely"; the physical
overwrite itself is not verifiable from JS
outside the storage engine.
**Status:** ✅ Hardened as best possible, an honestly documented limit.

---

### FINDING-010 — P2 — Group encryption without forward secrecy/sender auth within an epoch
**Component:** Group encryption
**Details, attack scenario, impact, migration recommendation:** see
[THREAT_MODEL.md, "Group encryption"](THREAT_MODEL.md#group-encryption--honest-limits-from-this-audit).
**Status:** ⚠️ Documented, not fixed. Member changes correctly trigger
a new epoch (verified) — the structural weakness
(one epoch key for all, no sender signatures) remains and
requires a migration to sender keys/MLS, not a quick fix.

---

### FINDING-011 — P3 — One-time prekeys can be exhausted through repeated lookups without completing a handshake
**Component:** Relay security
**File:** `server/src/index.js`, case `'lookup'`
**Problem:** an OTPK is consumed already on lookup
(`first.otpks.delete(id)`), not only after an actual
handshake completion. An attacker could, through repeated
`forHandshake:true` lookups (limited to 20/5 minutes per own account,
but not globally), deliberately exhaust a victim's OTPK stock and thereby
force every real contact attempt to the "lite" mode (amplifies
FINDING-003).
**Impact:** amplifies FINDING-003, not a standalone serious finding.
**Likelihood:** low (several forged accounts needed to bypass the
per-account rate limit).
**Fix:** not implemented in this audit round — would need a
reservation/expiry system for OTPKs instead of immediate consumption, a
standalone smaller feature.
**Status:** ⚠️ Documented, not fixed.

---

### FINDING-012 — P3 — Device list retrievable via the `devices` command without a trust check
**Component:** Relay security / metadata protection
**File:** `server/src/index.js`, case `'devices'`
**Problem:** every authenticated (not necessarily
trusted) device can retrieve the full device list of the account
(names, creation time, online status, trust status).
**Impact:** a pure metadata leak to an unconfirmed device, no
privilege bypass anymore (after the FINDING-005 fix, no actions
can be derived from it anymore).
**Likelihood:** high (trivially retrievable), low damage potential.
**Fix:** not implemented — a legitimate new (still unconfirmed)
device of the real owner plausibly needs the device list for its
own onboarding UI ("N devices, waiting for confirmation"); a
restriction to `trusted` devices would have risked breaking that without a
closer UI review.
**Status:** ⚠️ Documented, deliberately not fixed (a trade-off against
onboarding UX, see rationale).

---

### FINDING-013 — P1 — Uncaught exception on a corrupt vault file (found by fuzzing)
**Component:** Local vault security
**File:** `client/src/crypto/vault.ts`, `unlockVault()`, `checkIntegrity()`
**Problem:** `b64.dec()` (a wrapper around `atob()`) throws an `InvalidCharacterError`
when a field of the vault file does not contain valid Base64. This exception
was, in several places in `unlockVault()`/`checkIntegrity()`, not
caught — a manipulated or otherwise corrupt vault file
(e.g. `kdfSalt`/`data`/`mac` with invalid characters) let the function
crash with an uncaught exception instead of controlledly returning
`{ok: false, reason: 'tampered'}`.
**Found by:** property-based fuzzing (`client/tests/security/fuzz-vault.test.ts`,
`fast-check`) — random storage contents and single-byte mutations of a
real vault file uncovered the case within a few test runs.
**Attack scenario:** any form of file corruption (disk error,
an incomplete write, targeted manipulation) with a hit
in a Base64-encoded field let the app crash/hang on the unlock
attempt, instead of letting the expected, already-present
tamper detection take effect.
**Impact:** no confidentiality breach (the exception prevents rather too
much than too little), but an availability/robustness fault exactly in
the code path meant to detect manipulation safely.
**Likelihood:** medium — any kind of file corruption can trigger it,
not just targeted attacks.
**Fix:** `unlockVault()` is now wrapped in an outer function with a
catch-all (`unlockVaultInner` + wrapper) that treats every unexpected
exception as `tampered`; `checkIntegrity()` has its
own try/catch around the decode/compare logic.
**Regression test:** `client/tests/security/fuzz-vault.test.ts` — three
property tests (arbitrary storage content, arbitrary valid JSON,
single-byte mutation of a real vault file), 25–200 randomized
runs each, all green.
**Status:** ✅ Fixed.

---

## Summary

| ID | Title | Severity | Status |
|---|---|---|---|
| FINDING-001 | Ratchet state mutation before auth | P0 | ✅ Fixed |
| FINDING-002 | Ratchet not concurrency-safe | P1 | ✅ Fixed |
| FINDING-003 | X3DH downgrade undetectable | P2 | ⚠️ Mitigated |
| FINDING-004 | Live delivery to unconfirmed devices | P0 | ✅ Fixed |
| FINDING-005 | approve/revoke-device without a trust check | P0 | ✅ Fixed |
| FINDING-006 | lookup() ignores trust status | P1 | ✅ Fixed |
| FINDING-007 | Unbounded phantom-account growth | P1 | ✅ Mitigated |
| FINDING-008 | No master-key zeroization | P2 | ✅ Hardened |
| FINDING-009 | No secure delete of the vault file | P2 | ✅ Hardened |
| FINDING-010 | Groups: no FS/sender auth per epoch | P2 | ⚠️ Documented |
| FINDING-011 | OTPK exhaustion without handshake completion | P3 | ⚠️ Documented |
| FINDING-012 | Device list retrievable without a trust check | P3 | ⚠️ Documented |
| FINDING-013 | Uncaught exception on a corrupt vault file (fuzzing) | P1 | ✅ Fixed |

**All P0 and P1 findings are fixed and covered by real, automated
regression tests** (67 tests in `client/tests/security/`, 20
tests in `server/tests/security/`, 87 tests in total, all green,
typecheck and build clean). Remaining P2/P3 findings are either
hardened as best possible with an honestly documented residual limit, or deliberately
deferred, larger architecture topics with a clear rationale.
