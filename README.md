# 🛡 RenkerVault

![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Stack](https://img.shields.io/badge/stack-React%20%2B%20TypeScript%20%2B%20Tauri-blue)
![CI](https://github.com/sebastianrenker/renkervault/actions/workflows/security-ci.yml/badge.svg)
![Status](https://img.shields.io/badge/status-Prototyp%20%2F%20MVP-orange)

> Ende-zu-Ende-verschlüsselter Chat-Prototyp mit Zero-Knowledge-Relay, Post-Quantum-Handshake und Einbruchsalarm — Privatsphäre durch Architektur, nicht durch Vertrauen.

## Überblick

**RENKER INDUSTRIES — SECURE COMMS DIVISION.** Eigenständiger, Ende-zu-Ende-
verschlüsselter Chat-Prototyp mit Einzelchats, Gruppen, Broadcast-Kanälen und
einem **Einbruchsalarm-System** als Kernfeature. Selbst der Betreiber des
Relay-Servers hat **zu keinem Zeitpunkt Klartextzugriff** auf Nachrichten.

> ⚠ **Ehrliche Einordnung:** funktionsfähiger, sicherheitsbewusst gebauter
> **Prototyp/MVP** — **kein** extern auditiertes Produktionssystem und nicht
> „unhackbar". Grenzen: [SECURITY.md](SECURITY.md) · Architektur & Bedrohungs-
> modell im [Wiki](../../wiki).

**Warum ein Tool wie RenkerVault?** Der noch nicht verabschiedete EU-Vorschlag
[COM/2022/209](https://eur-lex.europa.eu/legal-content/DE/TXT/?uri=CELEX:52022PC0209)
(„Chat-Kontrolle") würde ein Scannen privater Inhalte für **alle** Anbieter
verpflichtend machen — auch für E2E-verschlüsselte Dienste, technisch nur über
**Client-Side-Scanning** vor der Verschlüsselung. RenkerVaults Architektur ist
bewusst so gebaut, dass ein solcher Zugriffspunkt **nicht existiert**: der
Relay-Server ist strukturell „blind" (Zero-Knowledge), es gibt keine Cloud-KI-
Klassifikatoren, und serverseitig gibt es nichts auszuwerten. Damit reiht sich
das Projekt bei datenschutzfreundlichen Alternativen (Signal, Session, Threema)
zur anlasslosen Massenüberwachung ein — nicht als Werkzeug „gegen" Kinderschutz.

## Features

| Bereich | Umsetzung |
|---|---|
| **1:1-Chats** | Ende-zu-Ende, Double-Ratchet-Prinzip (PFS + Post-Compromise Security); echte Kontakte über Konto-ID (X3DH-lite-Handshake) |
| **Gruppen** | Epoch-Keys („Sender-Keys-lite"); Mitglied rein/raus ⇒ automatische Schlüssel-Neuverteilung; granulare Admin-Rechte |
| **Kanäle** | Broadcast (Owner/Admins senden, Abonnenten read-only), verschlüsselt mit Kanal-Epoch-Key |
| **Nachrichten** | Text, verschlüsselte Anhänge, Sprachnachrichten, verschwindende Nachrichten; Lesebestätigungen & Tippindikator **standardmäßig AUS** (opt-in) |
| **Interaktionen** | Antworten/Zitieren, Bearbeiten, Löschen, Weiterleiten, Reaktionen, Anheften, @Erwähnungen |
| **Konto** | Lokal generierte ID + Passphrase — keine Telefonnummer, keine E-Mail |
| **Lokale Speicherung** | Verlauf verschlüsselt: Argon2id → AES-256-GCM, HMAC-Manipulationsschutz (nie Klartext auf der Platte) |
| **Schlüsselverifikation** | Safety Number (60 Ziffern) + QR pro Kontakt, „verifiziert"-Status |
| **Geräteverwaltung** | Geräteliste, manuelle Bestätigung neuer Geräte, sofortige Remote-Abmeldung |
| **🚨 Einbruchsalarm** | Brute-Force-Erkennung (5 Fehlversuche → Lockout + Alarm), Neu-Geräte-Erkennung, HMAC-Integritätsprüfung der DB, Duress-PIN mit Fake-Ansicht |

**„Chat-Kontrolle"-Härtung:** Post-Quantum-Hybrid-Handshake (X25519 + **ML-KEM-768**,
FIPS 203; schützt gegen „Harvest Now, Decrypt Later"), „Sitzung verbrennen (🔥)"
(sofortiges, unwiderrufliches Löschen inkl. Verschlüsselungssitzung) und **Tor
Hidden Service** als Hosting-Option. Bewusst NICHT implementiert (mit Begründung
in [SECURITY.md](SECURITY.md#4d-warum-es-kein-one-time-pad-und-keinen-quanten-zufallsgenerator-gibt)):
One-Time-Pad und ein „echter" Quanten-Zufallsgenerator.

## Architektur

```
renkervault/
├── client/                  React + TypeScript + Vite
│   └── src/
│       ├── crypto/          ← ALLE Kryptografie, isoliert
│       │   ├── primitives.ts   @noble/curves, @noble/hashes, hash-wasm, WebCrypto
│       │   ├── ratchet.ts      Double Ratchet + X3DH-Hybrid
│       │   ├── pq.ts           ML-KEM-768 (Post-Quantum-Hybrid-Handshake)
│       │   ├── vault.ts        At-Rest-Verschlüsselung + HMAC-Integrität + Duress
│       │   └── safety.ts       Safety Numbers / Fingerprints
│       ├── net/             WebSocket-Client + Echt-Sitzungs-/Gruppenschlüssel-Engine
│       ├── demo/seed.ts     Demo-Welt: simulierte Peers mit ECHTER Krypto
│       └── ui/              HUD-Dashboard-Komponenten
├── server/                  Zero-Knowledge-Relay (Node + ws): routet nur Chiffretext
├── deploy/                  Hosting: Caddyfile, systemd-Unit, DEPLOYMENT.md, torrc.snippet
└── installer/               Windows-Installer (Inno Setup)
```

**Zero-Knowledge-Prinzip:** Der Relay kennt nur Konto-IDs, öffentliche Schlüssel,
Geräte-Metadaten und opake Envelopes. Authentifizierung läuft **passwortlos** per
Ed25519-Challenge-Response — die Passphrase verlässt den Client nie.

**Wichtiger Kryptografie-Hinweis (ehrlich):** Es wird **keine eigene Primitive-
Kryptografie** implementiert — nur auditierte Bibliotheken (`@noble/*`, `hash-wasm`,
WebCrypto). Der Double-Ratchet in `crypto/ratchet.ts` ist jedoch eine **Komposition**
auditierter Primitive nach der öffentlichen Signal-Spezifikation — die Komposition
selbst ist **nicht extern auditiert**. Vor Produktiveinsatz: libsignal nativ
einbinden oder externes Audit. Vollständige Grenzen: [SECURITY.md](SECURITY.md).

## Quickstart

**Für alle (Windows, kein Vorwissen):**
[⬇ Installer herunterladen](../../releases/latest) → `RenkerVault_..._x64-setup.exe`
doppelklicken → dem Assistenten folgen. Läuft danach im lokalen Vorführmodus ohne
eigenen Server. (Windows-SmartScreen-Warnung = fehlendes kostenpflichtiges
Code-Signing, ehrlich benannt in [SECURITY.md](SECURITY.md).)

**Für Entwickler (macOS/Linux/Android/Anpassungen, Node.js ≥ 18):**

```bash
cd server && npm install && npm start      # Zero-Knowledge-Relay, Port 8787
cd client && npm install && npm run dev     # Vite-Dev-Server, Port 5173
```

Die App läuft auch **ohne** Relay (lokaler Demo-Modus). Für echte Chats muss der
Relay gemeinsam erreichbar laufen — VPS, eigener PC oder **Tor Hidden Service**,
Schritt für Schritt in [deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md). Relay-Adresse
in der App unter **Einstellungen → Relay-Server** (z. B. `wss://chat.deinedomain.de`).

**Desktop/Mobile aus derselben Codebasis:** Windows über [Tauri](https://tauri.app)
(`cd client && npx tauri build`, WebView2 statt Chromium), Android über
[Capacitor](https://capacitorjs.com) (`cd client/android && ./gradlew assembleDebug`,
läuft ohne Google Play Services, auch auf GrapheneOS).

## Tests

```bash
cd client && npm install && npm test    # vitest (Krypto/Logik)
cd server && npm install && npm test    # vitest (Relay)
```

## Lizenz

MIT — siehe [LICENSE](LICENSE). © 2026 Sebastian Renker.

## Über dieses Projekt

Ich bin 18 und habe RenkerVault als persönliches Lernprojekt gebaut, um
Ende-zu-Ende-Verschlüsselung nicht nur zu benutzen, sondern wirklich zu verstehen
— vom Double-Ratchet über den Post-Quantum-Hybrid-Handshake bis zur nativen
Windows-Hardware-Bindung (DPAPI) im Tauri-Backend. Entwickelt mit Claude Code als
KI-Pair-Programmer — ein Werkzeug wie eine IDE, kein Ersatz für eigenes Verständnis.
Mir war wichtig, nichts als sicherer zu verkaufen, als es ist: kein „unhackbar",
kein vorgetäuschtes Audit, offene Punkte klar benannt — siehe [SECURITY.md](SECURITY.md)
und das [Wiki](../../wiki).
