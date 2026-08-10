# SECURITY.md — Sicherheitsmodell & ehrliche Grenzen

Stand: Prototyp v0.1, nach dem Security-Hardening-Audit vom 10.08.2026.
Dieses Dokument beschreibt, **was wirklich geschützt ist**, welche
Kompromisse der Prototyp eingeht und was vor einem echten Produktiveinsatz
zwingend passieren müsste.

> Warum diese Architektur bewusst so gewählt wurde (Stichwort „Chat-Kontrolle"
> / verpflichtendes Client-Side-Scanning): siehe
> [README.md, Abschnitt „Hintergrund"](README.md#hintergrund-warum-ein-tool-wie-renkervault-gegen-chat-kontrolle).

> **Vertiefende Audit-Dokumente:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
> (was Relay/Tor/Cover-Traffic/PQ konkret schützen — und was nicht),
> [docs/METADATA.md](docs/METADATA.md) (feldweise Analyse, was der Relay
> aus jedem Envelope sieht), [docs/FINDINGS.md](docs/FINDINGS.md)
> (strukturierte Liste aller Audit-Befunde mit Schweregrad, Fix und
> Regressionstest). Automatisierte Sicherheitstests:
> `client/tests/security/` (39 Tests: Ratchet, Handshake, Vault) und
> `server/tests/security/` (12 Tests: Relay-Multi-Device-Trust,
> Auth-Flow, bounded storage) — `npm test` in `client/` bzw. `server/`.

---

## 1. Was ist wirklich Ende-zu-Ende-verschlüsselt?

| Bereich | Schutz | Details |
|---|---|---|
| 1:1-Chats | ✅ E2E, Double Ratchet | X3DH-Hybrid-Handshake (X25519 + ML-KEM-768, mit One-Time-Prekey wenn verfügbar, siehe Abschnitt 4b) → Double Ratchet (X25519 + HKDF-SHA256 + AES-256-GCM). Jede Nachricht eigener Message-Key (PFS); jeder Antwort-Roundtrip frischer Root-Key (Post-Compromise Security). Ratchet-Implementierung im Security-Audit vom 10.08.2026 geprüft und gehärtet (siehe [docs/FINDINGS.md](docs/FINDINGS.md), FINDING-001/002). |
| Gruppen | ⚠️ E2E, aber strukturell schwächer als 1:1 | Zufälliger 256-Bit-Gruppenschlüssel pro Epoche; jede Mitgliederänderung erzeugt verifiziert eine neue Epoche (Entfernte lesen nichts Späteres). **Ehrliche Grenze (Audit 10.08.2026):** kein Forward-Secrecy-Schutz *innerhalb* einer Epoche (ein kompromittierter Epoch-Key entschlüsselt alle Nachrichten der Epoche rückwirkend) und keine kryptographische Absender-Authentifizierung zwischen Mitgliedern. Für kleine, gegenseitig vertrauende Gruppen geeignet, nicht für Szenarien mit potenziell böswilligen Mitgliedern. Details + Migrationsempfehlung (Sender-Keys/MLS): [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/FINDINGS.md](docs/FINDINGS.md) FINDING-010. |
| Kanäle | ⚠ Verschlüsselt, aber schwächeres Vertrauensmodell | Kanal-Epoch-Key; Owner/Admins senden. Der Sender kennt zwangsläufig die Abonnentenliste; bei großen Kanälen ist der Schlüssel breit verteilt — eher „verschlüsselter Broadcast" als vertrauliche Kommunikation. |
| Lokale Datenbank | ✅ At-Rest | Argon2id (Passphrase) → KEK → wrappt zufälligen Master-Key → AES-256-GCM über den gesamten Zustand. HMAC-SHA256 über den Ciphertext als Manipulationsschutz. Kein Klartext auf der Platte. |
| Relay-Server | ✅ Zero-Knowledge | Sieht nur: Konto-IDs, öffentliche Schlüssel, Geräte-Metadaten, opake Envelopes. Auth per Ed25519-Challenge-Response (passwortlos). |

## 2. Einbruchsalarm-System (Kernfeature)

- **Brute-Force:** 5 fehlgeschlagene Entsperr-/Anmeldeversuche in kurzer Zeit →
  60 s Lockout + roter Vollbild-Alarm + Eintrag im Security-Log. Serverseitig
  identische Logik im Relay (Rate-Limit 30 msg/s pro Socket, Lockout-Broadcast
  an alle Geräte des Kontos).
- **Neue Geräte:** Jedes weitere Gerät ist zunächst `untrusted` und erhält
  weder die Offline-Warteschlange noch live zugestellte Nachrichten, bis es
  von einem bereits bestätigten Gerät manuell freigeschaltet wird. Meldet
  sich eine bekannte Geräte-ID mit anderem Schlüssel → `KEY_MISMATCH`-Alarm
  (möglicher Impersonations-Versuch). **Serverseitig durchgesetzt** seit dem
  Security-Audit vom 10.08.2026 — zuvor war die Bestätigungspflicht nur
  Client-UI-Konvention, der Relay selbst prüfte weder bei Live-Zustellung
  noch bei `approve-device`/`revoke-device` den Trust-Status des Aufrufers
  (siehe [docs/FINDINGS.md](docs/FINDINGS.md), FINDING-004/005/006 — P0,
  behoben, mit Regressionstests in `server/tests/security/relay.test.ts`).
- **DB-Manipulation:** HMAC-Prüfung beim Entsperren und auf Abruf. Fehlschlag
  → Alarm + optionaler Auto-Lockdown (nur Alarm-Screen sichtbar).
- **Duress-PIN:** separater Argon2id-Hash; die PIN öffnet eine leere
  Fake-Ansicht, der echte Tresor bleibt verschlossen. Es wird bewusst KEIN
  sichtbares Ereignis protokolliert.

## 3. Nachrichten-Interaktionen: Metadaten-Transparenz

Antworten, Bearbeiten, Löschen, Weiterleiten, Reaktionen und Präsenz sind
**Anwendungs-Events**, die wie normale Nachrichten über bestehende 1:1-/
Gruppen-Sitzungen laufen (Ratchet- bzw. Epoch-Key-verschlüsselt) — kein
separater Server-Mechanismus. Zwei bewusste Kompromisse dabei:

- **Antwort-Zitat und „Weitergeleitet von"-Name sind Envelope-Metadaten**,
  keine verschlüsselte Nutzlast — genau wie `msgId`, `fromName` und
  Dateiname/-größe, die der Relay ohnehin schon sieht (siehe Abschnitt 1).
  Emoji-Reaktion und neuer Bearbeitungstext dagegen laufen wie normale
  Nachrichten durch AES-GCM. Für echte Vertraulichkeit müsste auch die
  Zitat-Vorschau in die Ciphertext-Nutzlast wandern.
- **Präsenz ("online"/"zuletzt gesehen") ist Best-Effort und opt-in-artig
  implizit:** Der Relay speichert selbst KEINE Kontaktliste oder Präsenz —
  Clients senden sich Online-/Offline-Signale direkt gegenseitig über
  bestehende 1:1-Sitzungen. Offline-Signale beim Schließen der App/des Tabs
  sind nicht garantiert zustellbar (kein `beforeunload`-Warten auf Zustellung).
- **Angeheftete Nachrichten sind rein lokal** (nicht zwischen Geräten/
  Kontakten synchronisiert) — eine bewusste Vereinfachung gegenüber Telegram,
  wo Pins chatweit sichtbar sind.
- **Kein automatischer Linkvorschau-Abruf.** URLs werden nur klickbar
  gemacht, NIE serverseitig oder clientseitig automatisch abgerufen — das
  Nachladen von Metadaten einer verlinkten Seite würde die IP-Adresse und den
  Lesezeitpunkt an einen Dritten (den Linkbetreiber) leaken, unabhängig von
  der Ende-zu-Ende-Verschlüsselung des Chats selbst. Bewusste Abweichung von
  Telegrams Standardverhalten zugunsten der Privatsphäre.
- **Kanäle bleiben Demo-only** (siehe Abschnitt „Was ist wirklich verschlüsselt");
  ein Aufrufzähler für Broadcast-Nachrichten wurde daher nicht implementiert,
  da es ohne echte Mehrfachnutzer-Infrastruktur nichts Reales zu zählen gäbe.

## 3a. Sealed Sender für 1:1-Folgenachrichten

Ab der zweiten Nachricht einer bestehenden 1:1-Sitzung leiten beide Seiten
unabhängig voneinander ein kurzes Tag aus dem gemeinsamen Sitzungsgeheimnis
ab (`net/realchat.ts`: `deriveSessionTag`, HKDF über den Ratchet-Shared-
Secret). Der Client schickt dieses Tag statt sich auf die Konto-ID zu
verlassen; der Relay routet danach und schreibt die Konto-ID des Absenders
**nicht** mehr in die zugestellte bzw. zwischengespeicherte Nachricht
(`server/src/index.js`, Fall `'send'`) — der Empfänger löst sie stattdessen
selbst über `resolvePeerByTag` auf.

**Ehrliche Grenze:** Der Relay-*Betreiber* kennt den Absender einer
Nachricht trotzdem, weil das `send`-Kommando über eine bereits
authentifizierte, auf die Konto-ID lautende WebSocket-Verbindung eintrifft
— das lässt sich ohne ein System anonymer Zugangs-Credentials (blinde
Signaturen o. Ä.) nicht vermeiden und ist bewusst nicht implementiert
(deutlich größerer kryptographischer Aufwand, siehe Abschnitt 5). Was dieses
Feature tatsächlich bringt: Die Konto-ID landet nicht mehr als Klartext in
der zugestellten/zwischengespeicherten Nachricht selbst — ein Datenabzug
der Offline-Queue oder ein Log-Leck würde für Folgenachrichten keinen
Absender mehr preisgeben, selbst wenn der Betreiber live zusehen könnte.
Beim allerersten Kontakt (X3DH-Envelope) kennt die Gegenseite noch kein Tag
und braucht die Konto-ID zwingend, um überhaupt antworten zu können — dort
bleibt sie wie bisher server-sichtbar. Verifiziert per echtem
Zwei-Browser-Test (erste Nachricht `from` sichtbar, zweite `from: null`,
Empfänger löst trotzdem korrekt auf).

## 4. Bekannte Grenzen des Prototyps (bewusste Kompromisse)

1. **Double-Ratchet-Komposition ist nicht auditiert.** Primitive sind
   auditiert (@noble, hash-wasm, WebCrypto), die Protokoll-Komposition in
   `ratchet.ts` folgt der Signal-Spezifikation, wurde aber nicht extern
   geprüft. Es gibt derzeit keine gepflegte auditierte Signal-Browser-Library.
2. ~~X3DH-lite ohne One-Time-Prekeys~~ **Behoben:** Jede Identität hält einen
   Bestand von 25 Einmal-Prekeys (`net/realchat.ts`: `topUpOneTimePrekeys`),
   die beim Relay hinterlegt werden. Ein `lookup` mit `forHandshake=true`
   verbraucht genau EINEN davon und entfernt ihn serverseitig sofort aus dem
   Bestand (`server/src/index.js`, Fall `'lookup'`) — reine Info-Lookups
   (`forHandshake=false`, z. B. Kontaktnamen auffrischen) verbrauchen keinen.
   Der Handshake nutzt dann drei statt zwei DH-Berechnungen
   (`crypto/ratchet.ts`: `handshakeInitiator`/`-Responder`, dritter Term nur
   bei vorhandenem Einmal-Prekey, per eigenem HKDF-Info-String von der
   2-DH-Variante unterschieden). Ist der Bestand einer Gegenseite erschöpft,
   fällt der Handshake automatisch und unauffällig auf die 2-DH-Variante
   zurück (Signed Prekey allein) — funktional identisch zu vorher, aber ohne
   Fehlerfall. Verifiziert per Browser-Test (zwei echte Clients) und
   isoliertem Server-Test (Einmalausgabe, kein Verbrauch bei Info-Lookup,
   sauberes `null` bei leerem Bestand).
3. **Demo-Peers laufen im selben Browser-Prozess** (Nadja/Milan/Brandt/
   Werkstatt Nord/Bulletin) — echte Krypto, aber simulierte Gegenüber, nur zur
   Vorführung. Echte Kontakte/Gruppen (über „Kontakt hinzufügen") laufen
   dagegen wirklich über den Relay zwischen unabhängigen Client-Instanzen,
   inklusive persistierter Sitzungen (siehe `net/realchat.ts`).
4. **Demo-Ratchet-Sitzungszustand wird NICHT persistiert** (bewusst — jeder
   Neustart handelt neu aus, Safety Numbers bleiben stabil). **Echte
   Sitzungen und Gruppenschlüssel dagegen WERDEN persistiert** (verschlüsselt
   im Vault), da sonst zwei echte Gesprächspartner nach einem Neustart
   auseinanderlaufen würden.
5. **Memory-/Storage-Härtung (Audit 10.08.2026):** Der Master-Key wird beim
   Sperren/Zerstören des Vaults jetzt explizit im JS-Heap mit Nullen
   überschrieben (`crypto/vault.ts`, `zero()`), bevor die Referenz fällt;
   `destroyVault()` überschreibt den `localStorage`-Slot dreimal mit
   Zufallsdaten, bevor er entfernt wird. **Ehrlich dokumentierte Grenze:**
   Keine Garantie — V8s Garbage Collector und die WebCrypto-Implementierung
   können eigene, aus JS nicht erreichbare Kopien halten, und die
   Storage-Engine (LevelDB/SQLite-Backing) kann durch Compaction weiterhin
   ältere Kopien enthalten. Details: [docs/FINDINGS.md](docs/FINDINGS.md),
   FINDING-008/009.
6. **localStorage statt SQLCipher:** Browser-Prototyp. Das Schlüsselmodell
   (Argon2id → KEK → Master-Key → AES-GCM + HMAC) ist identisch übertragbar;
   eine Desktop-Variante (Tauri) sollte SQLCipher + OS-Keychain nutzen.
   **Bewusst noch nicht umgesetzt** (Härtungs-Roadmap Punkt 8): Das ist keine
   Kryptografie-Lücke — der Vault-Inhalt ist bereits vollständig AES-GCM-
   verschlüsselt, unabhängig vom Speicherort. Eine echte Migration bräuchte
   Rust-SQLite/SQLCipher-Bindings + Tauri-IPC-Kommandos + einen Migrationspfad
   für bestehende `localStorage`-Tresore, und ließe sich nur an einem
   tatsächlich gestarteten Tauri-Prozess korrekt verifizieren — nicht ohne
   diesen Test zu verantworten.
   ~~Hardware-gebundener Wrap-Layer (Härtungs-Roadmap Punkt 6)~~ — für
   Windows-Desktop seit diesem Update teilweise umgesetzt: `src-tauri/src/dpapi.rs`
   kapselt `CryptProtectData`/`CryptUnprotectData` (Windows-DPAPI, an
   Windows-Benutzerkonto + Gerät gebunden) als Tauri-Kommandos. `crypto/vault.ts`
   erkennt zur Laufzeit per `isTauri()`, ob eine native Desktop-Umgebung
   läuft, und legt dann den bereits KEK-gewrappten Master-Key zusätzlich in
   einer DPAPI-Schicht ab (`dpapiWrapped: true` im Vault-File) — eine
   kopierte Tresordatei ist auf einem anderen Gerät/Windows-Konto dann
   selbst mit korrekter Passphrase nicht mehr entschlüsselbar (neuer
   `UnlockResult`-Grund `device-mismatch`, bewusst NICHT als Fehlversuch in
   den Brute-Force-Zähler gezählt, da es kein Passphrasen-Problem ist). Im
   Browser-/Android-Build bleibt das Verhalten unverändert (kein DPAPI
   verfügbar, `dpapiWrapped: false`, reiner Argon2id-Pfad wie bisher) —
   vollständig rückwärtskompatibel zu bestehenden Tresoren.
   **Testabdeckung:** Die native DPAPI-Ebene selbst ist über vier echte
   `cargo test`-Fälle gegen die tatsächliche Windows-API verifiziert
   (Rundlauf, kein Klartext im geschützten Blob, Fehlschlag bei
   Manipulation, Leer-Eingabe). Der Browser-Fallback-Pfad (kein Tauri) ist
   per echtem End-to-End-Test verifiziert (Erstellen → Sperren →
   Entsperren). **Nicht verifizierbar in dieser Umgebung:** der vollständige
   Rundlauf *innerhalb* eines laufenden Tauri-Fensters (natives WebView2-
   Fenster, von den hier verfügbaren Browser-Automatisierungswerkzeugen
   nicht ansteuerbar) — vor Produktiveinsatz manuell auf echtem Windows mit
   `npm run tauri dev` nachzuholen. macOS (Keychain) und Android
   (Keystore) sind analog denkbar, aber nicht umgesetzt.
7. **Relay hält Zustand nur im RAM** (Prototyp): Konten/Queues gehen bei
   Neustart verloren. Produktion: PostgreSQL für Metadaten, persistente
   verschlüsselte Offline-Queues. **Seit dem Audit vom 10.08.2026 bounded
   statt unbounded:** eine harte Obergrenze für die Gesamtzahl verwalteter
   Konten (`MAX_TRACKED_USERS`, 200.000) sowie ein periodischer Sweep
   (alle 10 Minuten) entfernen abgelaufene Warteschlangen-Einträge (TTL
   14 Tage) und geräteloses Phantom-Konten — verhindert unbegrenztes
   Speicherwachstum durch Nachrichten an frei erfundene Ziel-userIds
   (siehe [docs/FINDINGS.md](docs/FINDINGS.md), FINDING-007). Eine echte
   Persistenzschicht bleibt trotzdem offen — das bounded-RAM-Verhalten ist
   eine Absicherung gegen Ressourcenerschöpfung, kein Ersatz für
   Neustart-Persistenz.
8. **Metadaten:** Der Relay sieht wer-mit-wem-wann (Routing). ~~Schutz
   dagegen (Sealed Sender...) ist nicht implementiert~~ — für 1:1-Folge-
   nachrichten seit diesem Update teilweise umgesetzt (Abschnitt 3a).
   ~~Padding und Cover-Traffic bleiben offen~~ — seit diesem Update ebenfalls
   umgesetzt (Abschnitt 4g). Weiterhin offen: Der Relay-*Betreiber* sieht
   nach wie vor live, welche authentifizierte Verbindung überhaupt eine
   `send`-Nachricht schickt (Timing des Verbindungsaufbaus selbst), Padding/
   Cover-Traffic verschleiern nur Größe und Sendehäufigkeit der Nachrichten
   danach, nicht die Tatsache der Verbindung an sich.
9. **Web-Auslieferung:** Eine Web-App kann vom Server kompromittiert
   ausgeliefert werden (malicious JS). Ernsthafter Einsatz braucht signierte
   Desktop-/Mobile-Builds (Tauri/Capacitor, siehe README „Deployment").
10. **Argon2id-Parameter** (64 MiB, t=4, siehe `crypto/primitives.ts`) sind ein
   Kompromiss zwischen Sicherheit und Entsperr-Latenz auf schwächerer
   Hardware; für einen dedizierten Produktivbetrieb weiter nach OWASP und
   Ziel-Hardware kalibrieren.
11. **Kein Schutz gegen kompromittiertes Endgerät.** Malware/Keylogger auf dem
    Gerät sieht alles — das kann keine E2E-Verschlüsselung verhindern.
12. **Anhang-/Sprachnachrichtengröße:** 1,2 MB Rohdaten pro Anhang (Prototyp-
    Obergrenze, siehe `MAX_FILE_BYTES` in `ui/App.tsx` und `MAX_MSG_BYTES` in
    `server/src/index.js`) — ausreichend für Bilder/kurze Sprachnachrichten,
    nicht für Videos.
13. **Relay-Rate-Limiting ist absichtlich einfach gehalten:** Verbindungs-
    deckel pro IP (20), Auth-Timeout (15 s), ein Pro-Socket-Nachrichtenlimit
    (30/s) sowie zwei zusätzliche, **kontobezogene** Limits (unabhängig von
    der Anzahl gleichzeitig verbundener Geräte desselben Kontos) — ein
    Sende-Limit (300 Nachrichten/Minute, verhindert das Fluten der
    Warteschlange eines einzelnen Ziel-Kontos) und ein Handshake-Lookup-Limit
    (20 pro 5 Minuten, verhindert gezieltes Leerräumen des One-Time-Prekey-
    Bestands eines Opfers, siehe Abschnitt 4 Punkt 2) — schützen vor
    trivialer Ressourcenerschöpfung durch einen einzelnen Angreifer. Es gibt
    weiterhin keinen Schutz gegen verteilte Angriffe (DDoS) aus vielen IPs —
    dafür ist ein vorgelagerter Reverse-Proxy/CDN mit DDoS-Schutz nötig.
    Konkrete, gestufte Optionen (ufw-Connection-Limit, fail2ban-Jail,
    CDN-Vorschaltung) jetzt in `deploy/DEPLOYMENT.md`, Abschnitt
    „DDoS-Schutz" dokumentiert; optionaler Caddy-Rate-Limit-Block in
    `deploy/Caddyfile` (braucht einen `xcaddy`-Custom-Build mit
    `caddy-ratelimit`-Plugin, vanilla Caddy hat kein eingebautes
    Rate-Limiting).

## 4a. TLS / Hosting für andere erreichbar machen

Der Relay unterstützt jetzt sowohl natives TLS (`TLS_CERT_FILE`/`TLS_KEY_FILE`)
als auch den empfohlenen Betrieb hinter einem Reverse-Proxy (Caddy mit
automatischem Let's-Encrypt-Zertifikat). Vollständige Schritt-für-Schritt-
Anleitung inklusive systemd-Hardening: [deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md).
**Wichtig:** `ws://` zu einem NICHT-lokalen Host überträgt den initialen
Handshake und alle Routing-Metadaten im Klartext — für alles außer
`localhost` ist `wss://` mit gültigem Zertifikat zwingend. Die App warnt
davor jetzt auch aktiv in den Einstellungen.

**TLS-Zertifikats-Pinning (Härtungs-Roadmap Punkt 7):** Für die
Android-Variante gibt es jetzt ein einkommentierbares `<pin-set>`-Template
in `android/app/src/main/res/xml/network_security_config.xml`. Standardmäßig
NICHT aktiv, weil Pinning eine fest einkompilierte Domain voraussetzt,
RenkerVaults Relay-Adresse aber in den Einstellungen frei wählbar ist —
sinnvoll nur für Betreiber, die eine eigene, gebrandete App-Variante mit
genau einem festen Relay ausliefern (Anleitung inkl. `openssl`-Befehl zum
Pin-Berechnen direkt in der Datei). Für den Browser-Prototyp und die
Tauri-Desktop-Variante (nutzt das System-WebView) existiert keine
öffentliche API für TLS-Pinning — eine Plattformgrenze, kein fehlendes
Feature dieses Projekts.

Für maximale IP-Anonymität (weder der Server noch ein Netzwerk-Beobachter
sieht die echte IP-Adresse der Gesprächspartner) gibt es zusätzlich
**Weg 3: Tor Hidden Service** (`deploy/torrc.snippet` +
[deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md)) — der Relay läuft dann
ausschließlich unter einer `.onion`-Adresse, komplett ohne öffentlichen
DNS-Namen oder offenen Port.

## 4b. Schutz gegen Quantencomputer (Post-Quantum-Hybrid-Handshake)

Der initiale Schlüsselaustausch (X3DH-lite) ist seit diesem Update
**hybrid**: klassisches X25519-ECDH **plus** ML-KEM-768 (FIPS 203, vormals
Kyber; auditierte Implementierung aus `@noble/post-quantum`), beide
Shared Secrets zusammen durch HKDF-SHA256 gemischt (`crypto/pq.ts`,
`crypto/ratchet.ts`). Das ist derselbe Ansatz, den Signal unter dem Namen
„PQXDH" produktiv einsetzt.

- **Warum überhaupt, wenn heutige Quantencomputer das noch nicht können?**
  Wegen „Harvest Now, Decrypt Later" (HNDL): ein Angreifer kann schon heute
  mitgeschnittenen Ciphertext speichern und erst in einigen Jahren mit einem
  ausreichend großen Quantencomputer entschlüsseln. Der Handshake muss also
  *heute* quantensicher sein, damit Nachrichten von heute auch in zehn
  Jahren geschützt bleiben.
- **Was ist NICHT PQ-geschützt:** Nur der Erstkontakt-Handshake nutzt ML-KEM.
  Die fortlaufenden Double-Ratchet-Schritte danach basieren weiterhin auf
  klassischem X25519-ECDH (wie bei Signal auch) — das ist eine bewusste,
  branchenübliche Grenze, kein Versehen. Ein Vollschutz des gesamten
  Ratchets gegen Quantenangriffe ist derzeit kein etablierter Standard.
- **Selbst wenn X25519 künftig gebrochen würde**, bliebe der Erstkontakt
  durch ML-KEM-768 sicher, solange dessen mathematische Annahme
  (Module-LWE) hält — daher „hybrid": es reicht, dass *eines* der beiden
  Verfahren hält.
- Verifiziert per echtem Zwei-Browser-Test über den Relay (siehe Abschnitt 1).

## 4c. Sitzung verbrennen (sofortige, unwiderrufliche Löschung)

Jeder Chat hat einen 🔥-Button (Doppelklick zum Bestätigen), der sofort und
unwiderruflich den kompletten lokalen Nachrichtenverlauf löscht. Bei echten
1:1-Kontakten wird zusätzlich die Verschlüsselungssitzung (Ratchet-Zustand)
und der Kontakt selbst entfernt — ein erneuter Kontakt erfordert einen
komplett neuen Handshake, es bleibt nichts von der alten Sitzung übrig.
Das entspricht dem „als wäre es nie passiert"-Prinzip von OnionShare/Tor:
nach dem Verbrennen existiert kein Beweis mehr, dass die Konversation
stattgefunden hat (abgesehen davon, dass der Relay ohnehin nur Metadaten,
nie Klartext, sieht — siehe Abschnitt 1).

## 4d. Warum es KEIN One-Time-Pad und KEINEN „Quanten-Zufallsgenerator" gibt

Diese beiden Konzepte wurden bewusst geprüft und NICHT implementiert —
hier die ehrlichen Gründe, statt sie stillschweigend weg zu lassen:

- **One-Time-Pad (OTP):** mathematisch perfekt sicher (Shannon), aber nur
  unter einer Bedingung, die in der Praxis fast nie eingehalten wird: der
  Schlüssel muss genau so lang wie die Nachricht sein, **wirklich** zufällig,
  und darf **kein einziges Mal** wiederverwendet werden. Für Chat-Nutzung
  (potenziell beliebig viele Nachrichten) müsste vorab eine riesige Menge
  Schlüsselmaterial sicher ausgetauscht werden (z. B. persönlich per USB-
  Stick, wie im Video als „Codebook" beschrieben) — und die geringste
  Wiederverwendung eines Blocks bricht die gesamte Sicherheit. Der
  Double-Ratchet-Ansatz, den RenkerVault stattdessen nutzt, erreicht einen
  in der Praxis vergleichbaren Schutz (jede Nachricht eigener Schlüssel,
  siehe Abschnitt 1), ohne das Schlüsselaustausch-Problem des OTP — deshalb
  keine OTP-Option in der App.
- **„Quanten-Zufallsgenerator" (QRNG):** Ein echter QRNG braucht spezielle
  Hardware (z. B. Quanten-Rauschen einer Photodiode) und lässt sich nicht in
  Software/im Browser realisieren — jede Software, die behauptet,
  „Quanten-Zufall" zu erzeugen, ohne solche Hardware auszulesen, macht eine
  falsche Behauptung. RenkerVault nutzt stattdessen `crypto.getRandomValues()`
  (ein kryptografisch sicherer Pseudozufallsgenerator, CSPRNG), was der
  korrekte und in der Kryptografie-Praxis (inkl. Signal, TLS, etc.)
  Standardansatz ist. Es besteht kein bekannter praktischer Sicherheitsgewinn
  durch echten Quantenzufall gegenüber einem CSPRNG für diesen Einsatzzweck.

## 4e. Kompatibilität mit gehärteten/alternativen Betriebssystemen

Die Android-App hat **keine Abhängigkeit von Google Play Services oder
Firebase** (kein Push-Dienst, keine Analytics-SDKs) und funktioniert daher
unverändert auf de-googelten Systemen wie **GrapheneOS**. Eine
`network_security_config.xml` erzwingt zusätzlich `wss://` für jeden Host
außer `localhost`/`127.0.0.1`/`10.0.2.2` (Emulator-Alias) — Klartext-`ws://`
ist nur auf dem eigenen Gerät erlaubt, defense-in-depth zur App-eigenen
Warnung in den Einstellungen.

## 4f. Dependency-Pinning & Supply-Chain-Prüfung

Höchste Priorität der [Härtungs-Roadmap](docs/inventions/RenkerVault-Haertungs-Roadmap.md)
auf der technischen Schiene: Eine kompromittierte transitive Abhängigkeit
von `@noble/curves`, `@noble/hashes`, `@noble/post-quantum` oder
`hash-wasm` würde jede andere Härtungsmaßnahme wertlos machen (reale
Präzedenzfälle: `event-stream` 2018, `ua-parser-js` 2021).

- **Exakte Versionspins:** Alle direkten Abhängigkeiten in `client/package.json`
  und `server/package.json` sind auf exakte, aktuell installierte Versionen
  fixiert (keine `^`/`~`-Ranges mehr) — ein `npm install` zieht damit nicht
  mehr automatisch neue Minor-/Patch-Versionen nach, die ungeprüft ins Projekt
  einfließen könnten. `package-lock.json` bleibt zusätzlich als zweite,
  transitive Pinning-Ebene bestehen.
- **`npm audit`-Ergebnis (Stand dieses Updates):** Server-Abhängigkeiten
  0 Findings. Client-Abhängigkeiten: 6 Findings in reiner Build-Tooling-Kette
  (esbuild/vite/postcss/tar/nanoid/brace-expansion, alle transitiv über Vite),
  **keine** in den kryptografierelevanten Laufzeit-Paketen
  (`@noble/*`, `hash-wasm`, `react`, `@capacitor/*`, `@tauri-apps/*`). Vier
  davon (brace-expansion, nanoid, postcss, tar) sind ohne Breaking Change
  behoben.
- **Bewusst offen gelassen:** Die verbleibenden zwei Findings (`esbuild`
  moderate, `vite` high — Vite ≤6.4.2 hängt von einer verwundbaren
  esbuild-Version ab) beträfen ausschließlich den lokalen Dev-Server
  (`npm run dev`: eine bösartige Website könnte im Browser des
  Entwicklers Anfragen an den Dev-Server stellen und Antworten mitlesen —
  betrifft NIE den produktiven Build oder Endnutzer). Der Fix verlangt einen
  Major-Sprung auf Vite 8, den `@vitejs/plugin-react` (aktuell 4.7.0) noch
  nicht offiziell als Peer-Dependency unterstützt (Range endet bei `^7.0.0`).
  Ein Test hat gezeigt: Der Sprung lässt sich zwar mit `--force` erzwingen und
  Build/Dev-Server laufen danach sogar fehlerfrei — aber jede zukünftige
  `npm install` ohne `--force` bräche danach dauerhaft mit einem
  ERESOLVE-Fehler. Dieser Tausch (dev-only-Lücke schließen gegen einen
  kaputten Standard-Installationsablauf für jeden künftigen Checkout) wurde
  bewusst NICHT gemacht — stattdessen bleibt Vite auf 5.4.21 gepinnt, bis
  `@vitejs/plugin-react` Vite 8 offiziell unterstützt. Erneut prüfen, sobald
  eine neue `@vitejs/plugin-react`-Version erscheint.
- **Kein automatisierter, wiederkehrender Check:** Es gibt (Stand jetzt)
  keine CI-Pipeline, die `npm audit` bei jedem Build automatisch ausführt —
  der Prototyp hat keine CI konfiguriert. Bis dahin: `npm audit` manuell in
  `client/` und `server/` vor jedem Release erneut ausführen.

## 4g. Padding & Tarn-Traffic (Metadaten-Minimierung, Fortsetzung von 3a/4f)

Härtungs-Roadmap Punkt 4, direkt aus dem README-Hintergrundabschnitt
begründet (Ziel: Überwachungsresistenz, nicht nur Inhalts-Vertraulichkeit).

- **Padding (`crypto/padding.ts`):** Jede Nachricht — Text, Datei,
  Gruppen-Nachricht und auch die internen Marker (`presence`, `deleted`,
  `reaction`) — wird vor der AES-GCM-Verschlüsselung auf eine von neun
  festen Größenstufen (64 B – 1,25 MiB) gepolstert. Der Relay sieht damit
  nur noch eine von wenigen Chiffretext-Größen statt der exakten
  Klartextlänge. ISO/IEC-7816-4-artiges Schema (0x80-Markerbyte +
  Nullbytes), keine eigene Kryptografie — reine Byte-Manipulation auf
  bereits fertigem Klartext. 40 isolierte Unit-Checks (Rundlauf an allen
  Stufengrenzen, leere Nachricht, Overflow, korrupte Daten) plus
  End-zu-Ende-Verifikation über zwei echte Browser-Clients.
- **Tarn-Traffic (`net/realchat.ts`, `ui/App.tsx`):** Poisson-artig
  gejitterte Dummy-Nachrichten (Mittelwert 60 s, 20–180 s Streuung) an
  zufällig gewählte, bereits bekannte Kontakte — Standard AN, in den
  Einstellungen abschaltbar. Entscheidend: Diese laufen als ganz normale
  `kind:'text'`-Envelopes; der Unterscheidungs-Marker steckt
  AUSSCHLIESSLICH in der Ende-zu-Ende-verschlüsselten Nutzlast (ein fester
  32-Byte-SHA-256-Wert), NICHT in einem eigenen Envelope-Feld — sonst
  könnte der Relay Tarn-Nachrichten trivial am Klartextfeld herausfiltern,
  genau das, was der Mechanismus verhindern soll. Der Empfänger erkennt
  und verwirft sie beim Entschlüsseln still (kein UI-Eintrag, kein
  Unread-Bump). Verifiziert per echtem Zwei-Browser-Test mit temporär
  verkürztem Intervall: mehrfacher bidirektionaler Tarn-Traffic-Austausch
  beobachtet, Chat-Verlauf zeigt danach weiterhin ausschließlich die
  tatsächlich gesendeten Nachrichten.
- **Ehrliche Grenze (identisch zu Kandidat D der Sicherheitserfindungs-
  Analyse):** Bei sehr wenigen Kontakten pro Konto bleibt die statistische
  Verschleierung schwächer als bei vielen. Kostet dauerhaft etwas
  Bandbreite/Akku, auch wenn niemand aktiv chattet. Verschleiert Größe und
  Sendehäufigkeit — verschleiert NICHT, dass überhaupt eine authentifizierte
  Verbindung zum Relay besteht (siehe Punkt 8 oben).

## 4h. Reproduzierbare Builds (Vorstufe zu signierten Builds, Härtungs-Roadmap Punkt 2)

- **Exakte Versionspins auch auf der Rust-/Tauri-Seite:**
  `src-tauri/Cargo.toml` fixiert jetzt ebenfalls exakte Versionen (`=x.y.z`
  statt Caret-Ranges) für `tauri`, `tauri-build`, `tauri-plugin-log`,
  `serde`, `serde_json`, `log`. Zusätzlich fixiert `src-tauri/rust-toolchain.toml`
  die exakte Rust-Toolchain-Version (`rustup` lädt sie bei Bedarf automatisch
  nach) — ohne diese Datei könnten verschiedene Maschinen mit
  unterschiedlichen `rustc`-Versionen aus demselben Quellcode
  unterschiedliche Binaries erzeugen.
- **Checksummen (`client/gen-checksums.mjs`, `npm run checksums`):**
  Erzeugt `SHA256SUMS.txt` über alle vorhandenen Build-Artefakte (Web-Dist,
  Tauri-Bundle, Android-APK/AAB). Ersetzt KEINE Code-Signatur — schützt
  nicht vor einem Angreifer, der sowohl Artefakt als auch Checksummen-Datei
  bei der Auslieferung kontrolliert. Sinn: Wer den Build selbst
  reproduziert, kann seinen Hash gegen einen unabhängig veröffentlichten
  (z. B. per GPG signierten Release-Eintrag) vergleichen.
- **Bewusst NICHT umgesetzt: echte Code-Signatur.** Das braucht reale
  Zertifikate (Windows Authenticode, Apple Developer Program, Android
  Play-Signing) — organisatorische Voraussetzungen (Registrierung,
  Identitätsprüfung, laufende Kosten), die kein Code-Schritt ersetzen kann.
  Build- und Toolchain-Reproduzierbarkeit sind die Vorstufe dazu, die jetzt
  steht; die eigentliche Signatur bleibt in Abschnitt 5 offen.

## 5. Vor Produktiveinsatz zwingend

- Externes Kryptografie-Audit (insbesondere `crypto/ratchet.ts`, `crypto/vault.ts`)
  **oder** Ersatz durch natives libsignal (Tauri/FFI).
- ~~Volles X3DH mit signierten Prekeys + One-Time-Prekeys~~ — seit diesem
  Update umgesetzt (Abschnitt 4, Punkt 2).
- TLS (wss://) ist verfügbar und sollte für jeden Betrieb außerhalb von
  `localhost` zwingend genutzt werden (siehe deploy/DEPLOYMENT.md).
  ~~Zertifikats-Pinning~~ — Android-Template seit diesem Update vorhanden
  (Abschnitt 4a), Browser/Tauri bleiben mangels Plattform-API offen.
  ~~DDoS-Schutz vor dem Reverse-Proxy~~ — gestufte Optionen seit diesem
  Update dokumentiert (deploy/DEPLOYMENT.md), echter Schutz gegen verteilte
  Angriffe bleibt nur über einen vorgeschalteten CDN-Dienst möglich.
  Weiterhin offen: persistenter Server-Store (PostgreSQL).
- ~~Sealed-Sender-artige Metadaten-Minimierung~~ — für 1:1-Folgenachrichten
  seit diesem Update umgesetzt (Abschnitt 3a), ~~Padding und Cover-Traffic~~
  ebenfalls (Abschnitt 4g). Erstkontakt-Nachrichten sowie Anonymität
  gegenüber dem live authentifizierenden Relay-Betreiber selbst bleiben
  offen (dafür wären anonyme Zugangs-Credentials nötig).
- Signierte Client-Builds — ~~reproduzierbare~~ Build-/Toolchain-Basis seit
  diesem Update vorhanden (Abschnitt 4h), die eigentliche Zertifikats-
  Signatur (Windows/macOS/Android) braucht reale, organisatorisch zu
  beschaffende Zertifikate.
- ~~Dependency-Pinning + Supply-Chain-Prüfung~~ — seit diesem Update umgesetzt
  (Abschnitt 4f).
- Hardware-gebundener Vault-Schlüssel und SQLCipher+OS-Keychain für die
  Tauri-Desktop-Variante — Architektur skizziert (Abschnitt 4 Punkt 6),
  Umsetzung bewusst zurückgestellt (nur auf echter Hardware/einem
  laufenden Tauri-Prozess verifizierbar, siehe docs/inventions/
  RenkerVault-Haertungs-Roadmap.md, Punkte 6 und 8).
- Threat-Model-Review (formal), Pen-Test des Relay — Scope-Dokument bereits
  vorhanden: [docs/inventions/RenkerVault-Audit-Vorbereitung.md](docs/inventions/RenkerVault-Audit-Vorbereitung.md).
- Migration der Gruppenverschlüsselung auf eine etablierte Konstruktion
  (Sender-Keys/MLS) — aktuelles Modell für kleine, vertrauende Gruppen
  ausreichend, nicht für Szenarien mit potenziell böswilligen Mitgliedern
  (siehe [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).
- **Externes** Kryptografie-Audit bleibt trotz des internen
  Security-Hardening-Audits vom 10.08.2026 offen — Details, was dieses
  interne Audit abgedeckt hat und was nicht, siehe
  [docs/THREAT_MODEL.md, Abschnitt „Auditierte vs. nicht auditierte
  Teile"](docs/THREAT_MODEL.md#auditierte-vs-nicht-auditierte-teile).

## 6. Meldung von Sicherheitslücken

Prototyp — Findings bitte direkt als Issue/Notiz an den Maintainer
(Renker Industries, intern).
