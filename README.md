# 🛡 RenkerVault

![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Stack](https://img.shields.io/badge/stack-React%20%2B%20TypeScript%20%2B%20Tauri-blue)
![CI](https://github.com/sebastianrenker/renkervault/actions/workflows/security-ci.yml/badge.svg)
![Status](https://img.shields.io/badge/status-prototype%20%2F%20MVP-orange)

> End-to-end encrypted chat prototype with a zero-knowledge relay, a post-quantum handshake, and a duress alarm — privacy by architecture, not by trust.

## Overview

**RENKER INDUSTRIES — SECURE COMMS DIVISION.** A self-contained, end-to-end
encrypted chat prototype with direct messages, groups, broadcast channels, and a
**duress-alarm system** as a core feature. Even the operator of the relay server
has **no plaintext access to messages at any point**.

> ⚠ **Honest framing:** a working, security-conscious **prototype/MVP** — **not**
> an externally audited production system, and not "unhackable". Limitations:
> [SECURITY.md](SECURITY.md) · architecture and threat model in the
> [Wiki](../../wiki).

**Why a tool like RenkerVault?** The still-pending EU proposal
[COM/2022/209](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52022PC0209)
("chat control") would make scanning private content mandatory for **all**
providers — including E2E-encrypted services, technically only achievable via
**client-side scanning** before encryption. RenkerVault's architecture is
deliberately built so that no such access point **exists**: the relay server is
structurally "blind" (zero-knowledge), there are no cloud AI classifiers, and
there is nothing to evaluate server-side. That places the project alongside
privacy-preserving alternatives (Signal, Session, Threema) opposed to suspicionless
mass surveillance — not as a tool "against" child protection.

## Features

| Area | Implementation |
|---|---|
| **1:1 chats** | End-to-end, Double Ratchet principle (PFS + post-compromise security); real contacts via account ID (X3DH-lite handshake) |
| **Groups** | Epoch keys ("sender-keys-lite"); a member joining/leaving ⇒ automatic key re-distribution; granular admin rights |
| **Channels** | Broadcast (owner/admins send, subscribers read-only), encrypted with a channel epoch key |
| **Messages** | Text, encrypted attachments, voice messages, disappearing messages; read receipts and typing indicator **off by default** (opt-in) |
| **Interactions** | Reply/quote, edit, delete, forward, reactions, pin, @mentions |
| **Account** | Locally generated ID + passphrase — no phone number, no email |
| **Local storage** | History encrypted: Argon2id → AES-256-GCM, HMAC tamper protection (never plaintext on disk) |
| **Key verification** | Safety number (60 digits) + QR per contact, "verified" status |
| **Device management** | Device list, manual confirmation of new devices, instant remote sign-out |
| **🚨 Duress alarm** | Brute-force detection (5 failed attempts → lockout + alarm), new-device detection, HMAC integrity check of the DB, duress PIN with a fake view |

**"Chat control" hardening:** post-quantum hybrid handshake (X25519 + **ML-KEM-768**,
FIPS 203; defends against "harvest now, decrypt later"), "burn session (🔥)"
(immediate, irreversible deletion including the encryption session), and a **Tor
hidden service** as a hosting option. Deliberately NOT implemented (with rationale
in [SECURITY.md](SECURITY.md#4d-warum-es-kein-one-time-pad-und-keinen-quanten-zufallsgenerator-gibt)):
a one-time pad and a "true" quantum random number generator.

## Architecture

```
renkervault/
├── client/                  React + TypeScript + Vite
│   └── src/
│       ├── crypto/          ← ALL cryptography, isolated
│       │   ├── primitives.ts   @noble/curves, @noble/hashes, hash-wasm, WebCrypto
│       │   ├── ratchet.ts      Double Ratchet + X3DH hybrid
│       │   ├── pq.ts           ML-KEM-768 (post-quantum hybrid handshake)
│       │   ├── vault.ts        at-rest encryption + HMAC integrity + duress
│       │   └── safety.ts       safety numbers / fingerprints
│       ├── net/             WebSocket client + real session/group-key engine
│       ├── demo/seed.ts     demo world: simulated peers with REAL crypto
│       └── ui/              HUD dashboard components
├── server/                  zero-knowledge relay (Node + ws): routes ciphertext only
├── deploy/                  hosting: Caddyfile, systemd unit, DEPLOYMENT.md, torrc.snippet
└── installer/               Windows installer (Inno Setup)
```

**Zero-knowledge principle:** the relay knows only account IDs, public keys,
device metadata, and opaque envelopes. Authentication is **passwordless** via an
Ed25519 challenge-response — the passphrase never leaves the client.

**Important cryptography note (honest):** **no custom primitive cryptography** is
implemented — only audited libraries (`@noble/*`, `hash-wasm`, WebCrypto). The
Double Ratchet in `crypto/ratchet.ts` is, however, a **composition** of audited
primitives following the public Signal specification — the composition itself is
**not externally audited**. Before production use: integrate libsignal natively or
get an external audit. Full limitations: [SECURITY.md](SECURITY.md).

## Quickstart

**For everyone (Windows, no prior knowledge):**
[⬇ Download the installer](../../releases/latest) → double-click
`RenkerVault_..._x64-setup.exe` → follow the wizard. It then runs in a local demo
mode without your own server. (The Windows SmartScreen warning = missing paid code
signing, stated honestly in [SECURITY.md](SECURITY.md).)

**For developers (macOS/Linux/Android/customization, Node.js ≥ 18):**

```bash
cd server && npm install && npm start      # zero-knowledge relay, port 8787
cd client && npm install && npm run dev     # Vite dev server, port 5173
```

The app also runs **without** a relay (local demo mode). For real chats the relay
must run reachable by all parties — a VPS, your own PC, or a **Tor hidden service**,
step by step in [deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md). Set the relay address
in the app under **Settings → Relay server** (e.g. `wss://chat.yourdomain.com`).

**Desktop/mobile from one codebase:** Windows via [Tauri](https://tauri.app)
(`cd client && npx tauri build`, WebView2 instead of Chromium), Android via
[Capacitor](https://capacitorjs.com) (`cd client/android && ./gradlew assembleDebug`,
runs without Google Play Services, including on GrapheneOS).

## Tests

```bash
cd client && npm install && npm test    # vitest (crypto/logic)
cd server && npm install && npm test    # vitest (relay)
```

## License

MIT — see [LICENSE](LICENSE). © 2026 Sebastian Renker.

## About this project

I built RenkerVault as a personal learning project to not just use end-to-end
encryption but genuinely understand it — from the Double Ratchet to the
post-quantum hybrid handshake to native Windows hardware binding (DPAPI) in the
Tauri backend. Developed with Claude Code as an AI pair programmer — a tool like an
IDE, not a substitute for my own understanding. It mattered to me not to sell
anything as more secure than it is: no "unhackable", no faked audit, open issues
named clearly — see [SECURITY.md](SECURITY.md) and the [Wiki](../../wiki).
