# 🛡 RenkerVault

**RENKER INDUSTRIES — SECURE COMMS DIVISION**

Eigenständiger, Ende-zu-Ende-verschlüsselter Chat-Prototyp mit Einzelchats,
Gruppen, Broadcast-Kanälen und einem **Einbruchsalarm-System** als Kernfeature.
Gebaut für Nutzer, die maximale Privatsphäre wollen: Selbst der Betreiber des
Relay-Servers hat **zu keinem Zeitpunkt Klartextzugriff** auf Nachrichten.

> ⚠ **Ehrliche Einordnung:** Dies ist ein funktionsfähiger, sicherheitsbewusst
> gebauter **Prototyp/MVP** — **kein** extern auditiertes Produktionssystem und
> nicht „unhackbar". Details und bekannte Grenzen: [SECURITY.md](SECURITY.md)
> · Architektur, Bedrohungsmodell und Krypto-Begründung ausführlich im
> [Wiki](../../wiki).

---

## Installation (für alle, kein technisches Vorwissen nötig)

**[⬇ RenkerVault für Windows herunterladen](../../releases/latest)**

1. Auf den Link oben klicken, dann bei „Assets" die Datei
   `RenkerVault_..._x64-setup.exe` anklicken.
2. Die heruntergeladene Datei doppelklicken und dem Installations-Assistenten
   folgen (überall „Weiter" klicken reicht).
3. Fertig — RenkerVault startet automatisch und legt eine Verknüpfung auf
   dem Desktop an.

Kein Node.js, kein Terminal, keine Kommandozeile nötig. Falls Windows beim
ersten Start warnt („Windows hat den Computer geschützt") liegt das daran,
dass die App noch kein kostenpflichtiges Code-Signing-Zertifikat hat (ehrlich
benannt in [SECURITY.md](SECURITY.md)) — auf „Weitere Informationen" →
„Trotzdem ausführen" klicken.

Die App funktioniert direkt danach im lokalen Vorführmodus, ganz ohne
eigenen Server. Für **echte** Chats mit einer anderen Person braucht ihr
einen gemeinsamen Server-Adresse (Details weiter unten unter „Echte
Kontakte & Gruppen").

*macOS/Linux sowie Android: siehe „Für Entwickler" unten — dafür gibt es
aktuell noch keinen fertigen Installer zum Herunterladen.*

---

## Hintergrund: Warum ein Tool wie RenkerVault gegen „Chat-Kontrolle"

Der [Bericht der Europäischen Kommission über die Durchführung der Verordnung
(EU) 2021/1232](https://home-affairs.ec.europa.eu/policies/internal-security/child-sexual-abuse/legal-framework-protect-children_en)
(zweiter Durchführungsbericht, 2025) zeigt, in welchem Umfang große Anbieter
(Google, Meta, Microsoft, LinkedIn, X, Yubo) bereits heute **freiwillig**
private Chatinhalte automatisiert durchsuchen: allein Microsoft verarbeitete
2024 weltweit 9,6 Milliarden Inhalte, Meta identifizierte 2023 3,6 Millionen
Inhalte als CSAM — bei gemeldeten Fehlerquoten (falsch positive Ergebnisse)
zwischen 0,1 % und über 1 % je nach Anbieter und Jahr. Das bedeutet: Bei
Milliarden gescannter Nachrichten/Bilder werden zwangsläufig auch tausende
komplett unbeteiligte Nutzer und legale Inhalte fälschlich markiert, Konten
gesperrt und Daten an Dritte (v. a. das US-amerikanische NCMEC) übermittelt.

Der noch nicht verabschiedete Folge-Vorschlag der Kommission
([COM/2022/209](https://eur-lex.europa.eu/legal-content/DE/TXT/?uri=CELEX:52022PC0209),
umgangssprachlich „Chat-Kontrolle") würde ein solches Scannen für **alle**
Anbieter interpersoneller Kommunikationsdienste **verpflichtend** machen —
auch für Ende-zu-Ende-verschlüsselte Dienste. Technisch ist das nur über
**Client-Side-Scanning** möglich: Der Inhalt wird auf dem Gerät des Nutzers
*vor* der Verschlüsselung bzw. *nach* der Entschlüsselung analysiert. Damit
entsteht ein struktureller Zugriffspunkt auf jeden privaten Chat — unabhängig
davon, wie stark die Übertragung selbst verschlüsselt ist, und unabhängig vom
ursprünglichen Verwendungszweck einer solchen Hintertür.

**RenkerVaults Architektur ist bewusst so gebaut, dass ein solcher
Zugriffspunkt technisch nicht existiert:**

- Der Relay-Server ist strukturell „blind" (Zero-Knowledge) — er kann nicht
  nachgerüstet werden, um Inhalte zu scannen, weil er nie unverschlüsselte
  Inhalte zu sehen bekommt (siehe [SECURITY.md](SECURITY.md), Abschnitt 1).
- Es gibt **keine** Cloud-KI-Klassifikatoren, die Nachrichten vor oder nach
  der Verschlüsselung analysieren — anders als bei den in obigem Bericht
  beschriebenen Anbietern.
- Das Sicherheitssystem (Alarm, Duress-Modus, Geräteverwaltung) schützt vor
  unbefugtem *Zugriff* auf das eigene Gerät — nicht vor der *Auswertung*
  fremder Inhalte, denn es gibt serverseitig nichts auszuwerten.

Das macht RenkerVault nicht zu einem Werkzeug „gegen" den Kinderschutz,
sondern zu genau der Art von Technologie (vergleichbar mit Signal, Session,
Threema), die Datenschutzorganisationen als Alternative zu anlassloser
Massenüberwachung privater Kommunikation vorschlagen: Schutz der Privatsphäre
aller Nutzer durch Architektur statt durch Vertrauen in eine Instanz, die
jederzeit missbraucht, ausgeweitet oder kompromittiert werden könnte.

---

## Für Entwickler: aus dem Quellcode starten

Nicht nötig, wenn du einfach nur chatten willst — dafür reicht der
Installer oben. Dieser Abschnitt ist für Entwicklung, macOS/Linux/Android
oder eigene Anpassungen.

Voraussetzung: Node.js ≥ 18.

```bash
# 1) Relay-Server (Zero-Knowledge-Relay, Port 8787)
cd server
npm install
npm start

# 2) Client (Vite-Dev-Server, Port 5173) — zweites Terminal
cd client
npm install
npm run dev
```

Dann http://localhost:5173 öffnen. **Die App funktioniert auch ohne laufenden
Relay** (lokaler Demo-Modus); der Relay liefert zusätzlich Geräteverwaltung,
serverseitige Brute-Force-Erkennung und kontoweite Security-Events.

### Erster Start (Demo-Ablauf)

1. **Tresor erstellen**: Konto-ID wird lokal generiert (keine Telefonnummer,
   keine E-Mail), Passphrase vergeben, optional Notfall-PIN (Duress-Modus).
2. Es werden automatisch **Demo-Daten** angelegt: 3 Einzelchats, 1 Gruppenchat
   („Werkstatt Nord"), 1 Kanal („RENKER BULLETIN") — jede Demo-Nachricht läuft
   real durch die Verschlüsselung (Button **CT** im Chat zeigt den Chiffretext).
3. **Alarm testen**: unten rechts „⚠ Intrusion simulieren" oder
   „DB-Manipulation simulieren" — oder beim Entsperren 5× die falsche
   Passphrase eingeben (→ Lockout + Alarm).
4. **Duress-Modus testen**: App sperren (🔒) und mit der Notfall-PIN statt der
   Passphrase entsperren → leere Fake-Ansicht, der echte Tresor bleibt zu.

### Echte Kontakte & Gruppen (Mehrgeräte-/Mehrbenutzer-Test)

Für einen echten Zwei-Personen-Test zwei Browser-Profile (oder zwei
Dev-Server-Ports, z. B. `npx vite --port 5174` in `client/`) gegen denselben
Relay laufen lassen, je einen Tresor anlegen, dann unter **Kontakte → Echten
Kontakt hinzufügen** die Konto-ID des anderen eintragen. Danach lassen sich
echte 1:1-Chats führen und über **„+ Gruppe"** echte Gruppen mit bereits
hinzugefügten Kontakten erstellen (Gruppenschlüssel wird automatisch über die
1:1-Sitzungen an jedes Mitglied verteilt).

### Für andere erreichbar machen (Hosting)

Standardmäßig läuft der Relay nur lokal (`ws://localhost:8787`) — für echte
Chats mit anderen Personen muss er auf einem gemeinsam erreichbaren Server
laufen. Zwei Wege, ausführlich Schritt für Schritt erklärt in
**[deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md)**:

- **Gemieteter VPS (empfohlen):** läuft 24/7, feste Domain, automatisches
  TLS-Zertifikat über einen Caddy-Reverse-Proxy, systemd-Dienst mit
  Sandbox-Härtung. Fertige Konfigurationsdateien in [deploy/](deploy/)
  (`Caddyfile`, `renkervault-relay.service`, `.env.example`).
- **Eigener PC:** möglich (Portweiterleitung + DynDNS), aber mit klaren
  Einschränkungen (kein 24/7-Betrieb, Heimnetz-Risiko) — Details und
  Sicherheitshinweise ebenfalls in DEPLOYMENT.md.
- **Tor Hidden Service (maximale Anonymität):** Relay läuft ausschließlich
  unter einer `.onion`-Adresse — weder eine Domain noch ein offener Port nach
  außen nötig, und niemand (auch kein ISP) sieht, wer mit wem verbunden ist.
  Fertiges `torrc`-Snippet in [deploy/torrc.snippet](deploy/torrc.snippet),
  Anleitung als „Weg 3" in DEPLOYMENT.md.

Die Relay-Adresse wird in der App unter **Einstellungen → Relay-Server**
eingetragen (z. B. `wss://chat.deinedomain.de`); alle Chat-Partner müssen
dieselbe Adresse verwenden. Die App warnt aktiv, falls eine unverschlüsselte
`ws://`-Verbindung zu einem nicht-lokalen Host konfiguriert wird.

### Desktop- & Mobile-Apps

Dieselbe Codebasis läuft zusätzlich als:

- **Windows-Desktop-App** über [Tauri](https://tauri.app) (`client/src-tauri/`)
  — natives Fenster mit WebView2 statt gebündeltem Chromium, dadurch kleinerer
  Angriffsvektor als bei Electron. Fertiger Installer: [Releases](../../releases/latest).
  Selbst bauen: `cd client && npx tauri build` (erzeugt direkt ein MSI und ein
  NSIS-Setup unter `src-tauri/target/release/bundle/`, kein zusätzliches
  Installer-Tool nötig).
- **Alternativer Windows-Installer** über Inno Setup (`installer/RenkerVault.iss`,
  optional) — bündelt die Tauri-App zusätzlich mit dem Relay-Server zum
  Selbstbetrieb (`start-relay.bat`). Braucht Inno Setup 6. Bauen:
  `ISCC.exe installer/RenkerVault.iss`.
- **Android-App** über [Capacitor](https://capacitorjs.com) (`client/android/`)
  — wrapped dieselbe React-Codebasis 1:1 in eine native WebView-App, keine
  Zweitimplementierung der Kryptografie nötig. Bauen: `cd client/android &&
  ./gradlew assembleDebug`. Läuft ohne Google Play Services/Firebase, damit
  auch auf **GrapheneOS** und anderen de-googelten Systemen; erzwingt per
  `network_security_config.xml` `wss://` für jeden Host außer dem eigenen
  Gerät.

---

## Schutz gegen Quantencomputer & Anonymität ("Chat-Kontrolle"-Härtung)

Direkt gegen die im Hintergrund-Abschnitt beschriebene Bedrohungslage
gerichtet, drei zusätzliche Bausteine:

- **Post-Quantum-Hybrid-Handshake:** Der Erstkontakt-Schlüsselaustausch
  kombiniert klassisches X25519 mit **ML-KEM-768** (FIPS 203) — derselbe
  Ansatz wie Signals „PQXDH". Schützt gegen „Harvest Now, Decrypt Later":
  heute mitgeschnittener Ciphertext bleibt auch dann sicher, wenn in einigen
  Jahren große Quantencomputer klassisches ECDH brechen könnten. Details
  und ehrliche Grenzen (nur der Handshake ist PQ-geschützt, nicht der
  fortlaufende Ratchet) in [SECURITY.md](SECURITY.md#4b-schutz-gegen-quantencomputer-post-quantum-hybrid-handshake).
- **Sitzung verbrennen (🔥):** Ein Klick (mit Bestätigung) löscht einen Chat
  sofort und unwiderruflich inkl. Verschlüsselungssitzung — „als wäre es nie
  passiert", analog zum OnionShare-Prinzip.
- **Tor Hidden Service** als Hosting-Option (siehe oben) für IP-Anonymität
  von Server und Metadaten.

Bewusst NICHT implementiert, mit Begründung: One-Time-Pad (praktisch
unhandhabbares Schlüsselaustausch-Problem) und ein „echter"
Quanten-Zufallsgenerator (braucht Spezialhardware, in Software nicht
umsetzbar — der eingesetzte `crypto.getRandomValues()`-CSPRNG ist der
korrekte Standardansatz). Ausführlich in
[SECURITY.md, Abschnitt 4d](SECURITY.md#4d-warum-es-kein-one-time-pad-und-keinen-quanten-zufallsgenerator-gibt).

## Was die App kann

| Bereich | Umsetzung |
|---|---|
| **1:1-Chats** | Ende-zu-Ende, Double-Ratchet-Prinzip (PFS + Post-Compromise Security); echte Kontakte über Konto-ID (X3DH-lite-Handshake) |
| **Gruppen** | Epoch-Keys („Sender-Keys-lite"); Mitglied rein/raus ⇒ automatische Schlüssel-Neuverteilung (neue Epoche); granulare Admin-Rechte (Senden/Einladen/Entfernen/Anheften) |
| **Kanäle** | Broadcast (Owner/Admins senden, Abonnenten read-only), verschlüsselt mit Kanal-Epoch-Key — Grenzen siehe SECURITY.md |
| **Nachrichten** | Text, verschlüsselte Datei-Anhänge (Bild-/Audio-Inline-Vorschau), Sprachnachrichten (Mikrofonaufnahme), verschwindende Nachrichten (Timer), Lesebestätigungen & Tippindikator **standardmäßig AUS** (opt-in) |
| **Nachrichten-Interaktionen** | Antworten/Zitieren, Bearbeiten, Löschen, Weiterleiten, Emoji-Reaktionen, Nachricht anheften (lokal), @Erwähnungen, klickbare Links (ohne automatischen Vorschau-Abruf — siehe SECURITY.md) |
| **Chat-Organisation** | Echte Vorschau der letzten Nachricht, Anpinnen, Stummschalten, Archivieren, Suche über Chatnamen + Nachrichteninhalte |
| **Präsenz** | Online-/Zuletzt-gesehen-Status pro echtem Kontakt (Best-Effort App-Protokoll, keine Server-seitige Präsenzliste) |
| **Konto** | Lokal generierte ID + Passphrase — keine Telefonnummer, keine E-Mail |
| **Lokale Speicherung** | Kompletter Verlauf verschlüsselt: Argon2id → AES-256-GCM, HMAC-Manipulationsschutz (nie Klartext auf der Platte) |
| **Schlüsselverifikation** | Safety Number (60 Ziffern) + QR-Darstellung pro Kontakt, „verifiziert"-Status |
| **Geräteverwaltung** | Geräteliste mit Online-Status; neue Geräte brauchen manuelle Bestätigung; Remote-Abmeldung sofort |
| **🚨 Einbruchsalarm** | Brute-Force-Erkennung (5 Fehlversuche → Lockout + Alarm), Erkennung neuer Geräte, HMAC-Integritätsprüfung der lokalen DB (→ optional Auto-Lockdown), Duress-PIN mit Fake-Ansicht — alles im Security-Log protokolliert |

## Architektur

```
renkervault/
├── client/                  React + TypeScript + Vite
│   └── src/
│       ├── crypto/          ← ALLE Kryptografie, isoliert (Begründung im Wiki)
│       │   ├── primitives.ts   Wrapper um @noble/curves, @noble/hashes,
│       │   │                   hash-wasm (Argon2id), WebCrypto (AES-GCM)
│       │   ├── ratchet.ts      Double Ratchet + X3DH-Hybrid (siehe Wiki: Kryptografie)
│       │   ├── pq.ts           ML-KEM-768 (Post-Quantum-Hybrid-Handshake)
│       │   ├── vault.ts        At-Rest-Verschlüsselung + HMAC-Integrität + Duress
│       │   ├── padding.ts      Nachrichten-Padding auf feste Größenstufen
│       │   └── safety.ts       Safety Numbers / Fingerprints
│       ├── net/
│       │   ├── client.ts       WebSocket-Client (Ed25519-Challenge-Response,
│       │   │                   Envelope-Zustellung, Kontakt-Lookup)
│       │   └── realchat.ts     Echte Sitzungs-/Gruppenschlüssel-Engine für
│       │                       echte Kontakte (persistiert im Vault)
│       ├── demo/seed.ts     Demo-Welt: simulierte Peers mit ECHTER Krypto
│       ├── state/           Typen
│       └── ui/              HUD-Dashboard-Komponenten
├── server/                  Zero-Knowledge-Relay (Node + ws)
│   └── src/index.js         Routet/queued ausschließlich Chiffretext;
│                            Brute-Force-Lockout, Geräteverwaltung, TLS-fähig
├── deploy/                  Hosting: Caddyfile, systemd-Unit, .env.example,
│                            DEPLOYMENT.md (VPS- und PC-Hosting-Anleitung)
└── installer/                Windows-Installer (Inno Setup, RenkerVault.iss)
```

**Zero-Knowledge-Prinzip:** Der Relay-Server kennt nur Konto-IDs, öffentliche
Schlüssel, Geräte-Metadaten und opake verschlüsselte Envelopes. Die
Authentifizierung läuft **passwortlos** per Ed25519-Challenge-Response — die
Passphrase verlässt den Client nie.

## Design

Dunkles Graphit/Anthrazit-HUD mit **Smaragdgrün/Cyan** als Akzent (bewusst
kein Violett — eigenständig gegenüber Rencora). **Signalrot existiert
ausschließlich im Alarmzustand**: Rot auf dem Bildschirm heißt immer „etwas
stimmt nicht". 6 Theme-Presets (Default/Dark/OLED/Light/Cyber/Minimal) +
Akzentfarben-Picker in der unteren Leiste. Zentrales Element ist eine
rotierende Schloss-/Schild-Visualisierung mit Partikel-Kette und sichtbarem
Schlüssel-Fingerprint statt eines KI-Radars.

## Wichtiger Kryptografie-Hinweis

Es wird **keine eigene Primitive-Kryptografie** implementiert — nur auditierte
Bibliotheken (`@noble/curves`, `@noble/hashes`, `hash-wasm`, WebCrypto).
**Aber:** Für das komplette Signal-Protokoll existiert derzeit keine gepflegte,
auditierte **Browser**-Bibliothek (libsignal-protocol-javascript ist archiviert,
`@signalapp/libsignal-client` ist ein natives Node-Modul). Der Double-Ratchet
in `client/src/crypto/ratchet.ts` ist daher eine **Komposition auditierter
Primitive nach der öffentlichen Signal-Spezifikation** — die Komposition selbst
ist **nicht extern auditiert**. Vor echtem Produktiveinsatz: libsignal nativ
einbinden (z. B. via Tauri) oder externes Audit. Der Erstkontakt-Handshake
nutzt zusätzlich `@noble/post-quantum` (ML-KEM-768) für Quantensicherheit —
ebenfalls eine auditierte Bibliothek, keine eigene PQ-Implementierung.
Vollständige Liste der Grenzen: [SECURITY.md](SECURITY.md).

## Über dieses Projekt

Ich bin 18 und habe RenkerVault als persönliches Lernprojekt gebaut, um
Ende-zu-Ende-Verschlüsselung nicht nur zu benutzen, sondern wirklich zu
verstehen — vom Double-Ratchet-Protokoll über den Post-Quantum-Hybrid-
Handshake bis zur nativen Windows-Hardware-Bindung (DPAPI) im Tauri-Backend.
Entwickelt mit Claude Code als KI-Pair-Programmer — genauso wie eine IDE
oder Dokumentation ein Werkzeug ist, nicht der Ersatz für eigenes
Verständnis. Ich kann jeden Teil dieses Repos erklären und begründen; das
Wiki dokumentiert bewusst nicht nur *was* gebaut wurde, sondern *warum*
(Bedrohungsmodell, Krypto-Komposition, ehrlicher Audit-Status inklusive
eines selbst gefundenen und behobenen Timing-Seitenkanals).

Was mir dabei besonders wichtig war: nichts als sicherer verkaufen, als es
ist. Kein „unhackbar", kein externes Audit vorgetäuscht, offene Punkte klar
benannt statt versteckt — siehe [SECURITY.md](SECURITY.md) und das
[Wiki](../../wiki).
