# THREAT_MODEL.md — What RenkerVault protects and what it does not

This document is the honest counterpart to [SECURITY.md](../SECURITY.md):
instead of "what was built", it concretely answers "what does this actually protect
against, and what not". As of: after the security-hardening audit of 2026-08-10
(see [FINDINGS.md](FINDINGS.md) for the individual findings of that audit).

## Attacker models

| # | Attacker | Capabilities |
|---|---|---|
| A1 | Passive network observer | Sees TLS-encrypted traffic to the relay, knows IP addresses and timing |
| A2 | Malicious/compromised relay operator | Sees everything the relay process sees (see the table below), can delay/duplicate/drop messages, but can NOT decrypt E2E ciphertext |
| A3 | Attacker who knows a victim's userId | userIds are deliberately shareable (like a contact name), so not a secret — see FINDING-006 |
| A4 | Compromised endpoint (malware/keylogger/physical access while unlocked) | Sees everything the app has in plaintext in memory |
| A5 | A current group member | Holds the current epoch key of the group |
| A6 | Future quantum attacker ("harvest now, decrypt later") | Records ciphertext today, decrypts in an estimated 10+ years with a cryptographically relevant quantum computer |

## What the relay sees (A2)

| Visible to the relay operator | NOT visible |
|---|---|
| The sender's account ID on the very first contact (X3DH envelope) | Message content (always, without exception, ciphertext) |
| The recipient's account ID (`to` field, mandatory for routing) | The sender's account ID for 1:1 follow-up messages (sealed sender, section 3a in SECURITY.md) |
| Time and frequency of connections/sends (timing) | The exact plaintext length (padding to 9 buckets, section 4g) |
| Envelope size (one of 9 padding buckets, not the exact length) | Whether a message is "real" or cover traffic (the marker is in the encrypted payload) |
| IP address (except when running as a Tor hidden service) | The group member list (only in the encrypted payload) |
| Device metadata (count, names, online status, trust status) | File names/types (since the padding update: the byte length of the payload incl. metadata JSON is padded, no longer directly proportional to the raw file) |
| Count + timing of `send` calls per account | Who has a group conversation with whom (the group chat ID is random, no plaintext member list in the envelope) |

**Important, newly corrected by this audit:** until this update, a
*technically unconfirmed* device add for any account (as long as the
userId is known) could self-authorize and read live every incoming
message of the account (envelope metadata AND — after completing its
own handshake — also ciphertext, which would however still not be decryptable
without the victim's real vault keys). That was a bug in the
server-side trust model, not an accepted trade-off — see
FINDING-004/FINDING-005 in [FINDINGS.md](FINDINGS.md). Fixed.

## What a compromised endpoint sees (A4)

Absolutely everything: decrypted messages in the UI, the unlocked
master key in process memory (as long as the vault is unlocked), every
input (keylogger), the clipboard. **No E2E encryption can
prevent this** — this is not a RenkerVault-specific limitation, but applies to
any software running on a compromised device.

After locking (`lockVault()`), the master key in the JS heap is overwritten
with zeros before the reference drops (see FINDING-008) — this shortens
the window for a memory dump, but does NOT guarantee complete
removal: V8's garbage collector and the internal WebCrypto implementation
can hold their own copies unreachable from JS. An attacker with
full access to an *unlocked* device gains nothing from this
hardening anyway — it acts exclusively for the period AFTER locking.

## What Tor protects — and what not

**Protects:** the user's IP address from the relay operator AND
from any network observer between the user and the relay (when running
as an `.onion` hidden service, see `deploy/torrc.snippet`). Without Tor, the
relay operator always sees the real IP.

**Does NOT protect:** against endpoint correlation by the relay operator itself
(it sees anyway which authenticated account sends when — Tor
hides only the IP, not the account ID). Does not protect against timing analysis
between two users who BOTH run over the same relay (a global
passive observer with visibility into the entire relay traffic could
correlate send/receive times — cover traffic mitigates this, but does not
eliminate it fully, see below). Does not protect against
endpoint compromise (A4).

## What cover traffic protects — and what not

**Protects:** obscures (statistically, not cryptographically provably)
*exactly when* real communication takes place, by mixing dummy messages of
plausible frequency/size in between, indistinguishable from the
relay's view (the marker is in the encrypted payload, see section 4g in
SECURITY.md).

**Does NOT protect:** the fact that an authenticated
WebSocket connection to the relay exists at all (that is visible in any client-server model).
Does not protect with very few contacts (statistical
obscuring is much weaker with 1-2 contacts than with 20). Is
NOT a substitute for a mixnet — an attacker with global visibility into the
entire relay traffic AND sufficient compute time for statistical analysis
over many days could possibly still distinguish real from cover-traffic
patterns. Costs some bandwidth/battery continuously.

## What post-quantum hybrid (ML-KEM-768) protects — and what not

More precise than SECURITY.md section 4b, with the separation required by the audit:

| Component | PQ-protected? |
|---|---|
| X3DH first-contact handshake (shared secret for session setup) | ✅ Yes — X25519 + ML-KEM-768 hybrid, HKDF-mixed |
| Double-Ratchet steps afterwards (every further DH-ratchet round) | ❌ No — pure X25519, as in Signal too |
| Identity authentication (who is my conversation partner) | ❌ No — Ed25519 signatures (classical), no PQ signature scheme in use |
| Vault encryption (Argon2id/AES-256-GCM) | Not applicable — AES-256 is already considered PQ-resistant (Grover provides only a quadratic rather than exponential speedup), no KEM/ECC involved |

**Downgrade resistance (newly checked by this audit):** X3DH can run with or
without a one-time prekey ("full" vs. "lite", separated via HKDF domain separation
— see `crypto/ratchet.ts`). A malicious relay could
in principle silently downgrade every handshake to "lite" by
never delivering an available one-time prekey on lookup — for this
there is currently only a heuristic detection (FINDING-003: a warning when
an incoming handshake arrives without an OTPK, although one's own OTPKs are available),
no cryptographic downgrade protection. The ML-KEM element itself
is unaffected by this downgrade question (it is always
included in both modes, independent of the OTPK).

## Group encryption — honest limits (from this audit)

Verified: member changes (add/remove) correctly trigger a
new key epoch that is re-distributed to the remaining members
(`ui/App.tsx`: `rotateRealGroup`) — a removed member indeed can no longer read
subsequent messages (post-compromise
security at the epoch boundary).

**What is NOT provided**, compared to an established construction like
Signal's sender keys or MLS:

- **No forward secrecy within an epoch.** All messages of an
  epoch use the same static AES-256-GCM key. If this
  key is ever compromised (e.g. via a compromised
  member device), ALL messages of that epoch are readable retroactively —
  not just future ones. The 1:1 chat does not have this weakness (every message has
  its own ratchet message key).
- **No cryptographic sender authentication within the group.**
  The group key is symmetric and shared by all members —
  any member could technically encrypt a message displayed
  in the client as "from person X" without a signature proving it
  (`fromName` is an envelope metadata field, not a signed claim).
  Signal's sender keys solve this via a separate signature key per
  member — not present here.
- **No protection against a current, malicious member sharing the
  group key outside the app** (e.g. with an already
  removed member) — inherent to any shared symmetric key,
  not solvable RenkerVault-specifically without a sender-keys/MLS model.

**Recommendation for real group use with more than "acquaintance-circle" trust:**
migration to an established group construction (Signal sender keys or
IETF MLS/RFC 9420) instead of the current "one epoch key for all" solution. That
is a standalone, multi-week architecture project (a new
key-distribution protocol, per-member ratchet chains,
client-side group-state management) and was deliberately
NOT rebuilt quickly in this audit, to avoid introducing unaudited cryptography
"quickly". Until then: **groups in RenkerVault are suitable for small,
mutually trusting groups, not for scenarios in which a
member itself could potentially be malicious.**

## Audited vs. non-audited parts

| Part | Status |
|---|---|
| Cryptographic primitives (`@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, `hash-wasm`, WebCrypto AES-GCM) | ✅ Externally audited, established libraries — no in-house implementation |
| Protocol composition (Double Ratchet, X3DH hybrid in `crypto/ratchet.ts`) | ⚠️ Internal hardening audit 2026-08-10 (this document + FINDINGS.md) — NO external crypto audit by a third party |
| Relay protocol (`server/src/index.js`) | ⚠️ Internal hardening audit 2026-08-10, real integration tests against the running process — NO external pen test |
| Vault/storage (`crypto/vault.ts`) | ⚠️ Internal hardening audit — NO external audit |
| Group encryption | ⚠️ Knowingly insufficient for high-security group scenarios (see above) — no migration in this audit |
| DPAPI hardware binding (Windows) | ✅ Native layer verified via `cargo test`; a full in-app round trip not testable in this environment |

Before a real production deployment with a relevant threat model (see
README "Background"), an **external cryptography audit by a
third party** remains the most important open measure — an internal audit, however
thorough, does not replace it.
