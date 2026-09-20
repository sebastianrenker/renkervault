# SECURITY_HARDENING_PLAN.md

As of: 2026-08-11. This document builds directly on two already
existing, current analyses instead of repeating them:
[SECURITY_AUDIT.md](../SECURITY_AUDIT.md) (a 14-attacker threat model,
a primitive-by-primitive analysis, a full findings catalog) and
[docs/FINDINGS.md](FINDINGS.md) (findings from the previous
hardening pass). What is new here: the implementation status since
SECURITY_AUDIT.md (several P1/P2 findings have been fixed since, see
section 3) and the new strategic question from this task —
human/agent/device/service identity and renker-core integration — which
**does not exist** in the current code and is deliberately documented here only as
a target architecture, not implemented.

## 1. Current architecture (as-is, verified in the code)

```
client/src/
  crypto/   primitives.ts (X25519/Ed25519/AES-GCM/HKDF/Argon2id wrappers,
            all @noble/* + hash-wasm + WebCrypto, no custom crypto)
            ratchet.ts (Double Ratchet + X3DH hybrid, a project-own
            composition of audited primitives)
            pq.ts (ML-KEM-768 via @noble/post-quantum)
            vault.ts (at-rest: Argon2id→KEK→master key→AES-GCM+HMAC,
            a generation counter against rollback, an optional DPAPI wrap)
            safety.ts, padding.ts
  net/      client.ts (Ed25519 challenge-response to the relay),
            realchat.ts (session/group-key engine)
  ui/       React components (onboarding, chat, SecurityCenter, ...)
server/src/index.js   Node/ws relay, RAM-only with bounded storage,
                       Ed25519 auth, multi-device trust enforced
                       server-side
client/src-tauri/     Tauri desktop shell, DPAPI IPC commands, now with
                       an explicit CSP
```

**Identity model (as-is):** there is exactly ONE identity type
(`state/types.ts`: `Identity`) — a human account identity with
embedded device fields (`deviceId`, `deviceName`). There is **no**
separation between human, agent, service, or session identity in the
code — this concept currently exists only as a target picture in this
document (see section 6). Every `createVault()` execution creates a
completely new, independent key bundle; there is no
client flow to attach a second device to an existing identity
(SECURITY_AUDIT.md, section 0).

## 2. Threat model (reference)

Fully in [SECURITY_AUDIT.md](../SECURITY_AUDIT.md) section 1
(14 attackers) and [docs/THREAT_MODEL.md](THREAT_MODEL.md) (relay/Tor/
cover-traffic/PQ protection limits). Not duplicated here. The core statement is
unchanged: the relay is structurally blind to plaintext (not
"zero-knowledge" in the cryptographic sense, but without access to
ratchet/group keys — the term is deliberately avoided in the docs,
see section 8).

## 3. Known weaknesses — implementation status since SECURITY_AUDIT.md

| Finding | Severity | As of SECURITY_AUDIT.md | Current status |
|---|---|---|---|
| GROUP-A (epoch rollback) | P1 | open | ✅ fixed (`realchat.ts`, monotonic epoch check + test) |
| VAULT-CSP (Tauri CSP null) | P1 | open | ✅ fixed (explicit CSP set, build verified) |
| RELAY-ORIGIN | P2 | open | ✅ fixed (`verifyClient`, opt-in `ALLOWED_ORIGINS`) |
| RELAY-ENUM | P2 | open | ✅ fixed (a dedicated lookup rate limit) |
| STORAGE-ROLLBACK | P2 | open | ✅ fixed (a generation counter, migration for the old format) |
| RATCHET-A (crash persistence) | P2 | open | ✅ fixed (immediate `saveVault` instead of a 400 ms debounce after every session change) |
| PASSPHRASE-ROTATE | P2 | open | ✅ fixed (`changePassphrase()` + UI in SecurityCenter) |
| CI-MISSING | P2 | open | ✅ fixed (`.github/workflows/security-ci.yml`: npm audit, typecheck, tests, build, `cargo check`, Gitleaks; `.github/dependabot.yml`) |
| RATCHET-B (snapshot sanity) | P3 | open | ✅ fixed (`fromSnapshot` validates ns/nr/pn) |
| ARGON2-ERR | P3 | open | ✅ fixed (`KdfExecutionError`, its own `UnlockResult` reason) |
| **PREKEY-ROTATE** | P2 | open | ❌ **still open** |
| **PREKEY-SIG** | P2 | open | ❌ **still open** |
| **DEVICE-PAIRING** | P2 (feature gap) | open | ❌ **still open** |
| SAFETY-NUM | P3 | open | ❌ still open (cosmetic, no security risk) |
| AAD-ENCODING | P3 | open | ❌ still open (fragility, no current bug) |
| SBOM-MISSING | P3 | open | ❌ still open |

For details/test coverage of each fixed point: the commit history of this
session or `client/tests/security/`, `server/tests/security/`
(currently 54 client + 16 server tests, all green — see section 7).

## 4. Security-critical components (unchanged, consolidated from SECURITY_AUDIT.md)

1. `crypto/ratchet.ts` — high-risk (a project-own protocol composition, no external audit)
2. `crypto/vault.ts` — at-rest key management
3. `server/src/index.js` — authorization decisions (trust, rate limits)
4. `crypto/pq.ts`, `crypto/primitives.ts` — pure library wrappers, no own crypto code
5. `net/realchat.ts` — group-key lifecycle

## 5. P0/P1/P2/P3 — consolidated priority list (remaining scope)

**P0:** no open P0 findings (both previous P0 bugs — ratchet-state
corruption, relay-trust bypass — are fixed and regression-tested).

**P1:** no more open P1 findings (GROUP-A, VAULT-CSP see section 3).

**P2 (the remaining scope of this planning):**
- PREKEY-SIG: the signed prekey is not signed by the identity key (a classical X3DH element missing)
- PREKEY-ROTATE: no automatic prekey rotation
- DEVICE-PAIRING: no client flow for "add a device to an existing identity" (a draft in SECURITY_AUDIT.md section 9)
- Identity-model separation (human/agent/device/service) — see section 6, NEW in this task

**P3:** SAFETY-NUM, AAD-ENCODING, SBOM-MISSING (see SECURITY_AUDIT.md)

## 6. Identity/agent architecture — target picture (phase 5 of this task, NOT implemented now)

**As-is:** a single, undifferentiated `Identity` type. No
concept of "agent" or "service" exists in the code, in the DB, in the
relay protocol, or in the documentation.

**Why not implemented directly here:** a clean separation of
human/agent/device/service/session identity is a
protocol extension, not a local hardening — it touches the
envelope format, the relay authorization logic, AND the
trust model (an agent must, as correctly required in the task,
NOT automatically receive the same rights as its human owner).
Introducing that "on the side" in the same pass as the rest of the P2 fixes
would be exactly the "large architecture rewrite without prior analysis"
explicitly forbidden in this task.

**Proposed target model** (for discussion, not final):

```ts
type PrincipalType = 'human' | 'agent' | 'device' | 'service';

interface Principal {
  type: PrincipalType;
  id: string;                // an own identity space per type, not globally unique across types
  publicKey: string;          // Ed25519 or X25519, depending on the purpose
  ownerId?: string;           // for 'agent'/'device': which 'human' owns/authorizes this — a mandatory field, never implicit
  capabilities?: string[];    // for 'agent'/'service': explicit, non-inherited rights
  createdAt: number;
  revokedAt?: number;
}
```

The core principle that must be hard-enforced in the implementation (when it
comes): **`ownerId` and `capabilities` are never
inherited implicitly from a `human` principal.** An agent acting in the name
of a human needs its own capability grant, separately
authorized and separately revocable in the relay — just as an
additional device already today (after the fixes in section 3) needs its
own, server-checked trust approval, not an automatically inherited one.

**Migration path (a sketch, not an implementation plan):**
1. Extend the `Identity` type with `principalType: 'human'` (backward-compatible, all existing accounts are implicitly `human`).
2. Extend the relay `hello` with an optional `principalType` + `ownerId` field; the server refuses `agent`/`service` logins without a valid authorization assertion signed by the `ownerId` principal.
3. Envelope routing stays unchanged (ciphertext routing is principal-agnostic) — only the authorization layer (who may send/receive/manage devices) is extended.
4. Safety numbers / fingerprints must also display the `principalType`, so that a user does not mistakenly take an agent for a human.

**renker-core integration:** `github.com/sebastianrenker/renker-core` was
not accessible from this environment at the time of this analysis
(no local checkout, no network access to the repo in
this session). An assessment of API compatibility, data models,
and versioning is not seriously possible without insight into the actual code of
renker-core — it is deliberately NOT guessed here,
but noted as an open point for a follow-up session with access to both
repositories. The crypto boundary (renker-core should not re-implement
cryptographic primitives, but if anything,
only access identity/permission/audit data models) is recorded here as a
guardrail, independent of the actual renker-core code.

## 7. Tests — present vs. missing

**Present (54 client + 16 server tests, as of this session):**
- `client/tests/security/ratchet.test.ts` (20): basic flow, out-of-order, packet loss, replay, tamper, simultaneous sending, session restore
- `client/tests/security/handshake.test.ts` (8): X3DH binding, domain separation, low-order-point rejection, KEM reject
- `client/tests/security/vault.test.ts` (18): duress, tamper, rollback protection, passphrase change, crash persistence
- `client/tests/security/group-security.test.ts` (5): epoch-rollback protection
- `client/tests/security/kdf-error.test.ts` (2): Argon2 error classification
- `server/tests/security/relay.test.ts` (13): auth flow, lockout, multi-device-trust-bypass regression, bounded storage, user-enumeration limit
- `server/tests/security/origin.test.ts` (3): origin validation

**Missing (scope for phase 4 "adversarial testing" of this task):**
- Fuzzing/property-based testing for wire/envelope parsing (section 9 in the original audit task of this series) — so far only hand-written malformed-input cases in the relay test, no systematic fuzzing (e.g. fast-check).
- Dedicated property/invariant tests in the style of the 8 invariants named in this task (e.g. "Revoked device can never create a trusted session") — the underlying guarantees are individually covered by existing tests, but not formulated as named, reusable invariant assertions.
- Device-specific scenarios "cloned device", "stolen session" — currently not distinguishable in the model (a cloned device with an identical `deviceId`+`edPub` looks to the server like a normal reconnection, see SECURITY_AUDIT.md threat #10).
- Identity/agent tests — not applicable as long as the feature does not exist (section 6).

## 8. Security maturity level (per area, honest, without overestimation)

| Area | Level | Rationale |
|---|---|---|
| Crypto primitives | **2 — Hardened** | Exclusively audited libraries, used correctly (see the primitive analysis in SECURITY_AUDIT.md) |
| Protocol composition (ratchet/X3DH) | **1 — Tested** | Extensively tested internally (28 targeted tests), but **no external audit** — must not be presented as "Hardened" or higher |
| Device trust | **2 — Hardened** | Enforced server-side since the last audit, but no pairing feature (level 1 for the UX side) |
| Identity (human/agent/service) | **0 — Prototype** | Does not exist in the code — only as a target picture in this document |
| Server/relay | **1 — Tested** | Authorization correct, but RAM-only, no pen test |
| Metadata privacy | **1 — Tested** | Known, documented gaps (METADATA.md), no structural solution (mixnet or similar) |
| Client (web/Tauri) | **1 — Tested** | CSP now set, but no SAST, no external pentest |
| Storage | **2 — Hardened** | Rollback protection, zeroization best-effort, Argon2id correctly parameterized |
| CI/CD | **1 — Tested** | The pipeline exists now (this session), but has never run in practice (no push since introduction) |

**No area reaches level 3 or 4.** This is a correct, not an overly
pessimistic assessment — an internal, however thorough,
audit does not replace an independent review (level 3), and certainly not a
proven production deployment under real load (level 4).

## 9. Next steps (phase 2 of this task)

The order per this plan: PREKEY-SIG → DEVICE-PAIRING →
identity-model scaffold (only the data model + documentation, not a
full agent platform) → fuzzing/property tests → doc sync.
