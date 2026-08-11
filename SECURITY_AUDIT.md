# SECURITY_AUDIT.md — Phase 1: Technische Security-Bestandsaufnahme

Stand: 11.08.2026. Dies ist eine **reine Analyse** — es wurde in diesem
Durchgang noch kein produktiver Code verändert. Basis: vollständige Lektüre
von `client/src/`, `client/src-tauri/`, `server/src/`, allen Tests,
`package.json`/Lockfiles/`Cargo.toml`, `tauri.conf.json`,
Build-/Release-Konfiguration, README.md, SECURITY.md sowie der bereits
bestehenden Audit-Dokumente aus einem vorangegangenen Hardening-Durchgang
(`docs/FINDINGS.md`, `docs/THREAT_MODEL.md`, `docs/METADATA.md`).

**Wichtiger Kontext für dieses Dokument:** Am 10.08.2026 gab es bereits
einen internen Hardening-Audit, der zwei kritische Bugs behoben hat (siehe
[docs/FINDINGS.md](docs/FINDINGS.md), FINDING-001 bis FINDING-012):

1. Double-Ratchet `decrypt()` veränderte den Sitzungszustand, bevor die
   AEAD-Authentifizierung geprüft war (State-Corruption durch ein
   einziges gefälschtes Paket möglich).
2. Relay `approve-device`/`revoke-device` prüften nicht, ob der Aufrufer
   selbst ein vertrauenswürdiges Gerät ist (vollständiger Bypass des
   Multi-Device-Vertrauensmodells).

Diese sind **bereits gefixt und mit Regressionstests abgedeckt** (51
Tests: 39 in `client/tests/security/`, 12 in `server/tests/security/`).
Dieses neue Audit baut darauf auf — es wiederholt diese beiden Funde nicht
als "neu", sondern prüft, was seitdem übersehen wurde, und geht in die
Tiefe bei Themen, die der letzte Durchgang nicht oder nur oberflächlich
behandelt hat: Device-Pairing-UX, CI/Supply-Chain-Automatisierung,
Fuzzing, Tauri-CSP/IPC-Härtung, Backup/Crash-Recovery, Prozess-/Log-Zugriff.

---

## 0. Wichtigster Einzelbefund dieses Durchgangs (vorab)

**Es gibt aktuell keinen Client-seitigen "Neues Gerät zu bestehendem Konto
hinzufügen"-Flow.** `Onboarding.tsx` → `CreateVault` generiert bei jedem
Aufruf eine komplett neue, unabhängige Identität: neue `userId`
(`newUserId()`), neues X25519-Identitätsschlüsselpaar, neues
Ed25519-Schlüsselpaar, neuen Prekey, neue `deviceId` (`uid('dev-')`) — alle
gemeinsam als ein Bündel. Es gibt kein Eingabefeld, um eine *bestehende*
`userId` zu übernehmen, keinen QR-Provisioning-Flow, keinen
Signal-artigen "Als verknüpftes Gerät anmelden"-Bildschirm.

Das bedeutet: Das serverseitige Multi-Device-Vertrauensmodell
(`approve-device`/`revoke-device`, siehe FINDING-004/005/006 im letzten
Audit) ist ein vollständig funktionierendes und jetzt korrekt
durchgesetztes **Server-Protokoll-Feature**, hat aber **keinen erreichbaren
Einstiegspunkt in der aktuellen Client-UI**. Der einzige praktische Weg,
zwei "Geräte" mit derselben `userId` zu erzeugen, wäre, die komplette
Vault-Datei (den `localStorage`-Eintrag, der `Identity` inklusive aller
privaten Schlüssel UND die `deviceId` enthält) manuell auf ein zweites
Gerät zu kopieren — das würde aber als **dasselbe** Gerät erscheinen
(identische `deviceId`, identischer `edPub`), nicht als neues,
bestätigungspflichtiges Gerät, und würde zusätzlich bedeuten, dass private
Identitätsschlüssel zwischen Geräten geteilt werden — architektonisch das
Gegenteil von Signals "jedes Gerät hat eigene Schlüssel"-Modell.

**Einordnung:** Das ist kein Sicherheitsloch im engeren Sinn (nichts wird
dadurch kompromittierbar, was nicht vorher schon so wäre) — es ist eine
**fehlende Funktion**, die aber Phase 6 dieses Audit-Auftrags ("Härten des
Device-Pairing-Systems") faktisch gegenstandslos macht, solange sie nicht
gebaut ist. Empfehlung für Phase 14: Bevor Device-Pairing "gehärtet"
werden kann, muss es erst als Feature existieren — mit einem
kryptographisch korrekten Provisioning-Protokoll (siehe Abschnitt 8
unten für einen konkreten Entwurf, orientiert an Signals
Device-Linking-Verfahren). Details siehe [Abschnitt 6](#6-device-pairing-analyse-des-ist-zustands).

---

## 1. Threat Model — 14 Angreifer

Bewertungsmaßstab Severity: **Kritisch** (bricht Vertraulichkeit/Integrität
des Kernversprechens), **Hoch** (bricht eine wichtige Nebeneigenschaft wie
Verfügbarkeit oder Multi-Device-Trust), **Mittel** (Metadaten-/
Privatsphäre-Einschränkung), **Niedrig** (theoretisch, hoher Aufwand oder
geringer Schaden).

### 1. Bösartiger Relay-Server

| | |
|---|---|
| **Geschützte Assets** | Nachrichteninhalt, Dateianhänge, Gruppenmitgliedschaft |
| **Angriffsvektor** | Betreiber kontrolliert `server/src/index.js` vollständig — kann jede Nachricht lesen, verändern, verzögern, duplizieren, verwerfen, umsortieren, falsche Lookup-Antworten liefern |
| **Aktuelle Schutzmaßnahme** | E2E-Verschlüsselung (Double Ratchet, Gruppenschlüssel) — Server sieht nie Klartext. Double-Ratchet-`decrypt()` verwirft jetzt (nach FINDING-001-Fix) manipulierte/gefälschte Nachrichten sicher, ohne den Sitzungszustand zu korrumpieren. `approve-device`/`revoke-device`/Live-Delivery sind seit FINDING-004/005 trust-geprüft. |
| **Verbleibendes Risiko** | Relay kann selektiv Nachrichten fallen lassen (Verfügbarkeits-, kein Vertraulichkeitsbruch) — vom Sender nicht direkt erkennbar (kein Zustellbestätigungs-/Sequenznummern-Mechanismus über den Ratchet-internen Zähler hinaus). Relay sieht weiterhin erhebliche Metadaten (siehe Abschnitt Metadaten in THREAT_MODEL.md). X3DH-Downgrade auf "lite"-Modus durch selektives Zurückhalten von OTPKs bleibt möglich (FINDING-003, nur heuristisch erkannt). |
| **Severity** | Mittel (Kern-Vertraulichkeit hält; Verfügbarkeit/Metadaten/Downgrade bleiben Restrisiken) |
| **Konkrete Verbesserung** | Zustellbestätigungen mit fortlaufenden, vom Client geprüften Sequenznummern pro Chat (erkennt selektives Droppen); kryptographisch bindende Prekey-Bundle-Signaturen mit Frische-Nachweis gegen den Downgrade (siehe FINDING-003). |

### 2. Passiver Netzwerk-Angreifer

| | |
|---|---|
| **Geschützte Assets** | Nachrichteninhalt, Verbindungsmetadaten |
| **Angriffsvektor** | Beobachtet Traffic zwischen Client und Relay (ISP, WLAN-Mitlauscher, Netzbetreiber) |
| **Aktuelle Schutzmaßnahme** | TLS (`wss://`) verpflichtend außerhalb von `localhost` (App warnt aktiv bei unverschlüsseltem `ws://` zu Remote-Hosts, siehe `Settings`). Envelope-Padding (9 Größenstufen) verschleiert exakte Klartextlänge. Cover-Traffic verschleiert Timing/Häufigkeit teilweise. |
| **Verbleibendes Risiko** | Ohne TLS (bewusst erlaubte lokale Entwicklungs-Option) voll im Klartext sichtbar. Selbst mit TLS: Verbindungsaufbau-Timing, Paketgrößen-Metadaten auf TCP-Ebene (TLS verschlüsselt Inhalt, nicht Paketgrößen/-timing vollständig), IP-Adressen beider Enden sichtbar (außer bei Tor-Hidden-Service-Betrieb). |
| **Severity** | Niedrig bei korrektem `wss://`-Betrieb; Kritisch bei versehentlichem `ws://`-Betrieb außerhalb localhost (durch App-Warnung mitigiert, aber nicht technisch verhindert — die Einstellung lässt sich trotzdem so setzen) |
| **Konkrete Verbesserung** | `ws://` zu Nicht-localhost-Hosts hart blockieren statt nur zu warnen (Downgrade von Warnung zu Verweigerung); TLS-Zertifikats-Pinning auch für Tauri/Browser prüfen, sobald Plattform-APIs das erlauben (aktuell nur Android-Template vorhanden). |

### 3. Aktiver Netzwerk-Angreifer (MITM)

| | |
|---|---|
| **Geschützte Assets** | Handshake-Integrität, Identitätsbindung |
| **Angriffsvektor** | Kann TLS-Verbindung terminieren (falls TLS selbst kompromittiert/falsch validiert ist), Pakete injizieren/modifizieren |
| **Aktuelle Schutzmaßnahme** | TLS schützt den Transport (Standard-Zertifikatsvalidierung des Browsers/WebView, kein Pinning außer Android-Template). X3DH bindet die Sitzung an Identitätsschlüssel; Safety Numbers erlauben manuelle Out-of-Band-Verifikation. |
| **Verbleibendes Risiko** | Ohne Zertifikats-Pinning bleibt ein Angreifer mit einer vom OS/Browser akzeptierten (z. B. durch eine kompromittierte/erzwungene Root-CA ausgestellten) TLS-Zertifikat-Fälschung theoretisch in der Lage, den WebSocket-Kanal zu terminieren und sich als Relay auszugeben — kann aber wegen E2E-Verschlüsselung weiterhin keine Nachrichteninhalte lesen, nur wie ein bösartiger Relay agieren (siehe Punkt 1). Ohne aktive Safety-Number-Verifikation durch die Nutzer bleibt eine Identitätsschlüssel-Substitution beim allerersten Kontakt (Trust-on-First-Use) unentdeckt. |
| **Severity** | Mittel (TOFU ist eine bewusste, dokumentierte Design-Entscheidung, kein Bug — aber Nutzer verifizieren Safety Numbers erfahrungsgemäß selten) |
| **Konkrete Verbesserung** | Safety-Number-Verifikation prominenter im UI verlangen (z. B. "unverifiziert"-Badge dauerhaft sichtbar statt nur im Kontaktdetail); TLS-Pinning für Desktop/Web evaluieren, sobald Plattform-APIs es erlauben. |

### 4. Kompromittiertes Benutzerkonto (gestohlene/erratene userId + Zugriff auf ein Gerät)

| | |
|---|---|
| **Geschützte Assets** | Kontoidentität, Multi-Device-Trust |
| **Angriffsvektor** | Angreifer kennt die (bewusst teilbare) `userId` eines Opfers und registriert sich per `hello` selbst als "Gerät" dieses Kontos |
| **Aktuelle Schutzmaßnahme** | Seit FINDING-004/005 (letzter Audit): Ein solches Gerät ist `untrusted`, erhält weder Live- noch Offline-Zustellung, kann sich nicht selbst freischalten und keine anderen Geräte entfernen. |
| **Verbleibendes Risiko** | Wie in Abschnitt 0 beschrieben: Da es aktuell **keinen Client-Flow gibt, der ein zweites Gerät legitim zu einem bestehenden Konto hinzufügt**, hat der Kontoinhaber selbst faktisch auch keine Möglichkeit, ein wartendes Gerät zu bestätigen — das UI zeigt zwar wartende Geräte in der Geräteliste (`SecurityCenter.tsx`) und einen `approve`-Button, aber der Kontoinhaber müsste erkennen, dass die Anfrage NICHT von ihm selbst stammt (reine Aufmerksamkeitsfrage, kein technischer Schutz zusätzlich zur bereits vorhandenen `NEW_DEVICE`-Alarm-Meldung). |
| **Severity** | Hoch → durch letzten Audit von Kritisch auf Hoch reduziert (kein automatischer Zugriff mehr, aber Social-Engineering-Restrisiko bleibt: Nutzer könnte eine Fremdanfrage versehentlich bestätigen) |
| **Konkrete Verbesserung** | Geräte-Bestätigungsdialog um ein Sicherheitsmerkmal erweitern, das Fremdanfragen schwerer plausibel macht als eigene (z. B. ein kurzer, nur dem echten zweiten Gerät bekannter Bestätigungscode statt reinem "Ja/Nein" — das ist genau das Kernstück eines echten Pairing-Protokolls, siehe Abschnitt 6). |

### 5. Kompromittiertes Endgerät (Malware/Keylogger/physischer Zugriff im entsperrten Zustand)

| | |
|---|---|
| **Geschützte Assets** | Alles — Klartext-Nachrichten, Master-Key, Passphrase-Eingabe |
| **Angriffsvektor** | Vollzugriff auf den Prozess, während der Vault entsperrt ist |
| **Aktuelle Schutzmaßnahme** | Keine (und keine denkbare) — E2E-Verschlüsselung kann Endgerät-Kompromittierung grundsätzlich nicht verhindern. Master-Key-Zeroization beim Sperren (FINDING-008) verkürzt das Zeitfenster NACH dem Sperren. |
| **Verbleibendes Risiko** | Vollständig — dokumentiert, nicht lösbar. |
| **Severity** | Kritisch, aber architektonisch unlösbar (jede Software auf einem kompromittierten Gerät ist betroffen) |
| **Konkrete Verbesserung** | Auto-Lock nach Inaktivität prüfen/verschärfen (aktuell vorhanden? siehe Code-Review-Punkt in Abschnitt 5 unten); OS-Keychain-Integration würde das Zeitfenster für Master-Key-Extraktion aus dem JS-Heap nicht verkleinern, da der Schlüssel während aktiver Nutzung ohnehin im Speicher liegen muss. |

### 6. Kompromittierter Peer (Gesprächspartner selbst ist böswillig oder dessen Gerät kompromittiert)

| | |
|---|---|
| **Geschützte Assets** | Nachrichten an ANDERE Kontakte/Gruppenmitglieder, eigene Identität |
| **Angriffsvektor** | Peer sieht per Definition alle mit ihm ausgetauschten Klartext-Nachrichten (das ist kein Bug — jeder E2E-Chat funktioniert so). Bei Gruppen: ein Mitglied besitzt den vollen Epoch-Key. |
| **Aktuelle Schutzmaßnahme** | 1:1: Kompromittierung eines Peers deckt nur dessen eigene Konversation auf, nicht andere Kontakte (jede 1:1-Sitzung hat eigene Ratchet-Kette). Gruppen: Mitgliederentfernung rotiert den Epoch-Key korrekt (verifiziert, `rotateRealGroup`). |
| **Verbleibendes Risiko** | **In Gruppen:** Ein böswilliges, aber noch nicht entferntes Mitglied kann Nachrichten fälschen, die im UI als "von Person X" erscheinen — der Epoch-Key ist symmetrisch, es gibt keine Absender-Signatur pro Mitglied (FINDING-010). Ein böswilliges Mitglied kann außerdem den Epoch-Key nach eigenem Ausschluss an Dritte weitergegeben haben, bevor die Rotation greift (inhärent bei jedem Shared-Key-Modell). |
| **Severity** | Mittel (1:1) / Hoch (Gruppen mit potenziell nicht vollständig vertrauenswürdigen Mitgliedern) |
| **Konkrete Verbesserung** | Migration der Gruppenverschlüsselung auf Sender-Keys/MLS (siehe Abschnitt 7) für echte Absender-Authentifizierung. |

### 7. Manipuliertes lokales Storage

| | |
|---|---|
| **Geschützte Assets** | Vault-Integrität, Vertraulichkeit gespeicherter Daten |
| **Angriffsvektor** | Direkter Dateizugriff auf den `localStorage`-Backing-Store (z. B. via anderer Software auf demselben Gerät, oder Wiederherstellung aus einem Backup) |
| **Aktuelle Schutzmaßnahme** | HMAC-SHA256 über den Ciphertext (`checkIntegrity()`, geprüft vor jedem Entsperren) erkennt Manipulation zuverlässig — Ergebnis `tampered`. AES-GCM selbst ist zusätzlich authentifiziert (doppelte Absicherung). |
| **Verbleibendes Risiko** | Erkennung ja, Wiederherstellung nein — eine manipulierte Datei ist schlicht nicht mehr entsperrbar (kein differenziertes Recovery, kein Diff gegen ein Backup). Kein Schutz gegen **Replay** eines älteren, aber gültigen (nicht manipulierten) Vault-Snapshots — der HMAC einer älteren, aber intakten Version prüft weiterhin korrekt "ok", das System kann also nicht erkennen, ob eine gültige Datei absichtlich durch eine ÄLTERE gültige Version ersetzt wurde (Rollback-Angriff auf den Vault selbst, nicht auf den Ratchet). |
| **Severity** | Mittel — Manipulationserkennung funktioniert, Rollback-auf-alte-gültige-Version bleibt unentdeckt (kein Monotonie-Zähler/Generation-Counter im Vault-Format) |
| **Konkrete Verbesserung** | Monoton steigenden Generation-Counter im `VaultFile`-Format ergänzen (bei jedem `saveVault` inkrementiert), der bei jedem Unlock gegen einen zuletzt gesehenen Wert geprüft wird — verhindert das unbemerkte Zurückspielen einer älteren, aber gültig signierten Version. |

### 8. Kompromittierte Dependency

| | |
|---|---|
| **Geschützte Assets** | Alles — eine kompromittierte Krypto-Bibliothek kann jede Garantie unterlaufen |
| **Angriffsvektor** | Bösartiger Code in `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, `hash-wasm`, `ws`, `tauri`, o. Ä. — direkt oder über eine kompromittierte transitive Abhängigkeit |
| **Aktuelle Schutzmaßnahme** | Exakte Versionspins (kein `^`/`~`) in `package.json` (client + server) und `Cargo.toml`. `npm audit`: 0 Findings in beiden Paketen (Produktions-Dependencies). Keine eigene Kryptografie-Implementierung — nur etablierte, weit verbreitete Bibliotheken. |
| **Verbleibendes Risiko** | Pinning schützt gegen automatisches Nachziehen kompromittierter NEUER Versionen, nicht gegen eine bereits zum Pin-Zeitpunkt kompromittierte Version. **Kein automatisierter, wiederkehrender `npm audit`/CI-Check** — Findings würden erst bei manueller Prüfung auffallen (siehe Abschnitt 9, kein `.github/workflows` vorhanden). Kein SBOM. Keine Signatur-/Provenance-Prüfung von npm-Paketen selbst (npm hat keine verpflichtende Paket-Signierung). |
| **Severity** | Hoch (kein technischer Fehler im Projekt selbst, aber eine reale, unadressierte Prozesslücke — reale Präzedenzfälle: `event-stream` 2018, `ua-parser-js` 2021, `xz-utils` 2024) |
| **Konkrete Verbesserung** | CI-Pipeline mit `npm audit --audit-level=high` als Pflicht-Check, Dependabot/Renovate für kontrollierte Update-PRs statt manueller Pins, SBOM-Generierung (siehe Phase 9/10 unten). |

### 9. Supply-Chain-Angreifer (kompromittiertes Build-/Release-System)

| | |
|---|---|
| **Geschützte Assets** | Integrität der ausgelieferten Binaries (Installer, APK) |
| **Angriffsvektor** | Angreifer mit Zugriff auf den Build-Rechner oder das GitHub-Release-Konto könnte manipulierte Binaries ausliefern |
| **Aktuelle Schutzmaßnahme** | `SHA256SUMS.txt` wird für Build-Artefakte erzeugt (`client/gen-checksums.mjs`). Rust-/Node-Toolchain-Versionen sind gepinnt (Vorstufe zu reproduzierbaren Builds). |
| **Verbleibendes Risiko** | **Keine Code-Signatur** (Windows Authenticode, Apple Developer, Android Play-Signing) — bereits in SECURITY.md als offen dokumentiert. Ohne Signatur kann ein Nutzer die Herkunft eines Installers nicht kryptographisch verifizieren, nur den Hash gegen eine (ebenfalls vom selben Betreiber veröffentlichte, also nicht unabhängige) Checksummen-Datei. Kein Build-Provenance-Nachweis (z. B. SLSA/Sigstore), keine GitHub Actions Artifact Attestation. Keine CI-Pipeline überhaupt (`.github/workflows` existiert nicht) — Releases werden aktuell manuell lokal gebaut und hochgeladen, was das Vertrauensmodell zusätzlich auf "vertraue dem Rechner des Maintainers" reduziert, ohne nachvollziehbaren, reproduzierbaren CI-Build-Log. |
| **Severity** | Hoch |
| **Konkrete Verbesserung** | Release-Build über GitHub Actions statt lokal (nachvollziehbarer Build-Log als Vertrauensanker), GitHub Artifact Attestations (kostenlos, baut auf Sigstore auf, kein eigenes Zertifikat nötig), perspektivisch echte Code-Signatur. |

### 10. Angreifer mit Zugriff auf Backups

| | |
|---|---|
| **Geschützte Assets** | Vault-Inhalt in Backups (z. B. Cloud-Sync des Browser-Profils, Windows-Dateisicherung) |
| **Angriffsvektor** | `localStorage`-Backing-Datei landet ungefragt in System-/Cloud-Backups (z. B. Browser-Sync, Windows-Systemwiederherstellung, WebView2-Profil-Backup) |
| **Aktuelle Schutzmaßnahme** | Der Vault-Inhalt ist bereits vollständig AES-256-GCM-verschlüsselt — ein Backup enthält nie Klartext, unabhängig vom Backup-Mechanismus. |
| **Verbleibendes Risiko** | Ein Angreifer mit Zugriff auf ein Backup UND der Passphrase kann den Tresor genauso entsperren wie auf dem Originalgerät — es gibt (bewusst, siehe Abschnitt 0) keine Geräte-/Hardware-Bindung, die das verhindert, AUSSER auf Windows-Desktop mit aktivierter DPAPI-Wrap-Schicht (dort schlägt das Entsperren mit `device-mismatch` fehl, wenn die Datei auf ein anderes Windows-Konto/Gerät kopiert wurde). Im Browser-/Android-Kontext (kein DPAPI) ist ein Backup vollständig portabel — reines Passphrasen-Wissen genügt. Das ist funktional identisch zu "Passphrase ist der einzige Schutz", was bei ausreichend starker Passphrase akzeptabel, aber nicht selbstverständlich ist (keine Mindestanforderung außer 8 Zeichen Länge, siehe `Onboarding.tsx`). |
| **Severity** | Mittel — abhängig von Passphrasenstärke, die aktuell nur auf Mindestlänge (8 Zeichen) geprüft wird, nicht auf Entropie/Wiederverwendung |
| **Konkrete Verbesserung** | Passphrasen-Stärkeindikator (z. B. zxcvbn-artige Schätzung) im Onboarding statt reiner Längenprüfung; DPAPI-artige Hardware-Bindung auch für macOS (Keychain) und Linux (Secret Service) nachziehen, wie in SECURITY.md bereits als offen dokumentiert. |

### 11. Angreifer mit Zugriff auf den laufenden Prozess (Debugger, Memory-Dump)

| | |
|---|---|
| **Geschützte Assets** | Master-Key, Ratchet-Session-Keys, Klartext im Speicher |
| **Angriffsvektor** | Debugger-Attach, Coredump, Swap-Datei-Analyse während die App läuft |
| **Aktuelle Schutzmaßnahme** | Master-Key-Zeroization beim Sperren (FINDING-008) — nur relevant für die Zeit NACH dem Sperren. Während des ENTSPERRTEN Betriebs: keine Schutzmaßnahme (technisch in JavaScript kaum möglich, siehe unten). |
| **Verbleibendes Risiko** | Während der Vault entsperrt ist, liegen Master-Key, alle aktiven Ratchet-Chain-Keys und entschlüsselte Klartexte zwangsläufig im JS-Heap — jeder Prozess-Debugger/Memory-Dump zu diesem Zeitpunkt kompromittiert alles. Das ist **keine RenkerVault-spezifische Schwäche**, sondern eine fundamentale Grenze jeder JavaScript-Laufzeit: Es gibt kein Äquivalent zu Rusts `zeroize`, `mlock()` (Speicher vor Swapping schützen) oder garantierter Stack-/Heap-Bereinigung. V8s Garbage Collector kann Objekte kopieren, bevor sie freigegeben werden, und die WebCrypto-Implementierung hält importierte Schlüssel intern in einer für JS nicht erreichbaren Form. |
| **Severity** | Kritisch während aktiver Nutzung, aber architektonisch nicht lösbar innerhalb von JavaScript/Browser/WebView |
| **Konkrete Verbesserung** | Ehrlich dokumentieren (siehe Abschnitt 5 unten — SECURITY.md muss das explizit als JS-Grenze benennen, nicht als "gelöst" verkaufen). Für die Tauri-Variante: sicherheitskritischste Operationen (Master-Key-Handling) perspektivisch in den Rust-Backend-Prozess verlagern (deutlich stärkere Speicher-Kontrolle als im WebView-JS-Kontext) — größeres Architekturprojekt, nicht kurzfristig. |

### 12. Angreifer mit Zugriff auf Logs

| | |
|---|---|
| **Geschützte Assets** | Metadaten, potenziell Secrets in Fehlermeldungen |
| **Angriffsvektor** | Zugriff auf Server-`console.log`-Ausgaben, Client-seitige Browser-DevTools-Konsole, Tauri-`tauri-plugin-log`-Dateien |
| **Aktuelle Schutzmaßnahme** | Server loggt nur `[GUARD] Lockout für <userId>`, `[ERR] <err.message>` — keine Payload-/Schlüssel-Logs gefunden. Client hat laut vorherigem Audit keine Debug-Logs mit Secrets (Kommentar-/Log-Bereinigung war Teil des letzten Hardening-Durchgangs). |
| **Verbleibendes Risiko** | `console.error('[ERR]', err.message)` im Server könnte bei bestimmten Fehlerpfaden (z. B. `JSON.parse`-Fehler mit dem Originalstring in der Fehlermeldung, oder ein zukünftig hinzugefügter Fehlerpfad) versehentlich Payload-Fragmente in Logs landen lassen — aktuell nicht der Fall, aber nicht durch eine strukturelle Regel (z. B. Linter-Regel gegen `console.log(msg)` mit rohem Nachrichtenobjekt) abgesichert, sondern nur durch Code-Review. `tauri-plugin-log` ist eingebunden, aber es wurde nicht geprüft, ob/wohin es standardmäßig schreibt und ob sensible IPC-Argumente geloggt werden könnten. |
| **Severity** | Niedrig (aktuell keine gefundene Leckage) bis Mittel (keine strukturelle Absicherung gegen zukünftige Regressionen) |
| **Konkrete Verbesserung** | Lint-Regel/Code-Review-Checkliste: niemals rohe Envelope-/Message-Objekte in `console.*` übergeben, nur ausgewählte, bekannt-unsensible Felder. `tauri-plugin-log`-Konfiguration explizit auf Debug-Build beschränken bzw. Log-Level/Ziel für Release-Builds prüfen. |

### 13. Bösartiger Gruppenadministrator

| | |
|---|---|
| **Geschützte Assets** | Gruppenmitgliedschaft, Nachrichtenintegrität innerhalb der Gruppe |
| **Angriffsvektor** | Ein `owner`/`admin`-Mitglied (siehe `MemberPermissions`: `canRemove`, `canInvite`, `canPin`) kann Mitglieder entfernen/hinzufügen und hat vollen Zugriff auf den aktuellen Epoch-Key |
| **Aktuelle Schutzmaßnahme** | Rollenmodell (`owner`/`admin`/`member`) mit granularen Berechtigungen existiert im Datenmodell (`state/types.ts`: `Member`, `MemberPermissions`). Epoch-Rotation bei Mitgliederänderung verifiziert korrekt. |
| **Verbleibendes Risiko** | Die Berechtigungsprüfung (`canRemove` etc.) ist rein **client-seitig** (im UI) — es gibt keine serverseitige oder kryptographische Durchsetzung, wer eine `group-key`-Verteilung auslösen darf. Ein Admin (oder ein Angreifer, der die Rolle client-seitig manipuliert, z. B. durch direkte Manipulation des lokalen Zustands vor einem Neustart) könnte theoretisch beliebig Mitglieder hinzufügen/entfernen, ohne dass andere Mitglieder das kryptographisch verifizieren können — sie vertrauen der `group-key`-Nachricht, weil sie über eine authentifizierte 1:1-Sitzung mit dem (vermeintlichen) Admin ankommt, nicht weil eine Rolle kryptographisch bewiesen wird. |
| **Severity** | Mittel (setzt bereits eine Gruppenmitgliedschaft voraus, kein Fremdangriff, aber ein böswilliger/kompromittierter Admin hat mehr Macht, als das UI suggeriert) |
| **Konkrete Verbesserung** | Rollenwechsel/Mitgliederänderungen signieren (mit dem Identitätsschlüssel des Admins) statt nur über den verschlüsselten Kanal zu verteilen — würde bei einer MLS-Migration (siehe Abschnitt 7) ohnehin mitgelöst. |

### 14. MITM während Device Pairing

| | |
|---|---|
| **Geschützte Assets** | Identitätsbindung eines neuen Geräts |
| **Angriffsvektor** | Ein Angreifer fängt die Kommunikation zwischen zwei Geräten desselben Nutzers während des Pairings ab |
| **Aktuelle Schutzmaßnahme** | **Nicht anwendbar — es existiert kein Device-Pairing-Flow** (siehe Abschnitt 0). Es gibt daher aktuell auch keinen MITM-Angriffsvektor GEGEN Pairing, weil nichts gepaart wird. |
| **Verbleibendes Risiko** | Sobald ein Pairing-Feature gebaut wird (Empfehlung siehe Abschnitt 6/8), MUSS es von Anfang an MITM-resistent entworfen werden (z. B. durch eine aus einem gemeinsamen Kanal — QR-Code direkt zwischen den Geräten — abgeleitete Bestätigung, NICHT nur über den bereits potenziell kompromittierten Relay). |
| **Severity** | Nicht bewertbar (Feature existiert nicht) — als **Design-Anforderung für Phase 14** vorgemerkt. |
| **Konkrete Verbesserung** | Siehe Abschnitt 8, Entwurf eines QR-basierten Provisioning-Protokolls mit Kanal-Bindung. |

---

## 2. Kryptografische Primitiv-Analyse

Jede Zeile: Input → Output → Encoding → Domain Separation → KDF-Kontext →
Key-Lifetime → Nonce-Lifetime → Fehlerverhalten. Quelle:
`client/src/crypto/primitives.ts`, `ratchet.ts`, `pq.ts`, `vault.ts`,
`safety.ts`, `padding.ts`.

### X25519 (`@noble/curves/ed25519`, Funktion `x25519`)
- **Input:** 32-Byte-Privatschlüssel (`x25519.utils.randomPrivateKey()`, aus `crypto.getRandomValues`), 32-Byte-Public-Key des Gegenübers.
- **Output:** 32-Byte-Shared-Secret (`x25519.getSharedSecret`).
- **Encoding:** Raw Bytes, Base64 für Transport/Speicherung (`b64.enc`/`.dec`).
- **Domain Separation:** Keine auf X25519-Ebene selbst nötig — erfolgt eine Ebene höher im HKDF-Info-String (siehe unten).
- **Fehlerverhalten (geprüft in diesem Audit):** `@noble/curves`s `scalarMult` wirft explizit `'invalid private or public key received'`, wenn das Ergebnis der Punkt niedriger Ordnung (Low-Order-Point, inkl. Null) ist — RFC-7748-konforme Validierung, verifiziert durch Code-Lektüre von `node_modules/@noble/curves/esm/abstract/montgomery.js` und durch einen Regressionstest (`handshake.test.ts`: "ein manipulierter DH-Public-Key mit niedriger Ordnung wird von X25519 abgelehnt"). **Kein Fund** — korrekt implementiert.
- **Key-Lifetime:** Identitätsschlüssel: dauerhaft (bis Konto-Neuerstellung). Prekey: dauerhaft, aber rotierbar (keine automatische Rotation implementiert — siehe Finding unten). One-Time-Prekey: einmalig, wird nach Konsum serverseitig gelöscht. Ratchet-DH-Schlüssel: pro Epoche (jeder DH-Ratchet-Schritt generiert einen neuen).

### ML-KEM-768 (`@noble/post-quantum/ml-kem.js`)
- **Input:** `ml_kem768.keygen()` liefert `{secretKey, publicKey}`; `encapsulate(publicKey)` liefert `{cipherText, sharedSecret}`; `decapsulate(cipherText, secretKey)` liefert `sharedSecret`.
- **Output:** 32-Byte Shared Secret (FIPS-203-konform).
- **Fehlerverhalten (geprüft):** ML-KEM nutzt implizite Ablehnung (Fujisaki-Okamoto-Transform) — ein manipuliertes `cipherText` führt NICHT zu einer Exception, sondern zu einem deterministisch falschen, aber gültig aussehenden Shared Secret. Verifiziert per Test (`handshake.test.ts`: "ein manipuliertes PQ-Ciphertext führt zu implizitem KEM-Reject"). Das ist **korrektes, spezifikationskonformes Verhalten** (Schutz gegen Padding-Oracle-artige Angriffe), kein Bug — wichtig, dass die höhere Protokollebene (Double Ratchet, AEAD-Tag-Prüfung) das falsche Secret trotzdem sicher als Fehlschlag erkennt, was der Fall ist (die resultierende erste Ratchet-Nachricht scheitert dann an der AES-GCM-Tag-Prüfung).
- **Domain Separation:** ML-KEM-Shared-Secret wird gemeinsam mit den X25519-DH-Ausgaben in EINEN HKDF-Aufruf gegeben (`concat(...parts)` inkl. `pqSecret`), mit domain-separiertem Info-String — kein eigener HKDF-Schritt für PQ allein. Das ist der etablierte "Hybrid"-Ansatz (wie Signals PQXDH), korrekt umgesetzt.
- **Key-Lifetime:** PQ-Prekey ist wie der klassische Prekey dauerhaft ohne automatische Rotation (gleicher Rotations-Finding wie oben).

### Ed25519 (`@noble/curves/ed25519`)
- **Verwendungszweck:** Ausschließlich für Relay-Authentifizierung (Challenge-Response: Server sendet Nonce, Client signiert mit `edPriv`, Server verifiziert mit `edPub`) — NICHT für Nachrichtensignaturen oder X3DH-Identitätsbindung (die läuft über X25519-DH, klassisch für X3DH).
- **Input/Output:** `ed25519.sign(msg, priv)` → 64-Byte-Signatur; `ed25519.verify(sig, msg, pub)` → boolean.
- **Nonce:** Serverseitig `crypto.randomBytes(32)` pro Verbindung, einmalig verwendet (`meta.nonce = null` nach Verifikation gesetzt) — kein Replay einer alten Challenge möglich, da der State nach Verbrauch gelöscht wird. **Korrekt.**
- **Fehlerverhalten:** `ed25519.verify` in einem `try/catch` gekapselt (`server/src/index.js`, Fall `'proof'`) — eine malformte Signatur/Nonce führt zu `ok = false`, nicht zu einer ungefangenen Exception. **Korrekt.**

### AES-256-GCM (WebCrypto `crypto.subtle`)
- **Nonce/IV:** 12 Byte, `rand(12)` = `crypto.getRandomValues` — pro Verschlüsselungsoperation frisch generiert, dem Ciphertext vorangestellt (`concat(iv, ct)`), beim Entschlüsseln wieder abgetrennt (`data.subarray(0, 12)`).
- **Nonce-Wiederverwendungsrisiko:** Bei zufälligen 96-Bit-Nonces und der Anzahl der Verschlüsselungsoperationen, die in einer App-Lebensdauer realistisch anfallen, ist eine Kollision nach dem Geburtstagsparadoxon (√(2^96) ≈ 2^48 Operationen für 50 % Kollisionswahrscheinlichkeit) praktisch ausgeschlossen — **kein Fund**, Standardvorgehen, identisch zu Signal.
- **AAD:** Ratchet-Header (`JSON.stringify(header)`) wird als Additional Authenticated Data mitgegeben — bindet Header-Integrität an den Ciphertext, ohne den Header selbst zu verschlüsseln (muss lesbar bleiben, um überhaupt entschlüsseln zu können). **Korrekt konstruiert**, aber die Verwendung von `JSON.stringify` statt eines kanonischen, festen Byte-Layouts ist eine Fragilitäts-Anmerkung (kein aktueller Bug, da Encoder/Decoder in dieser Codebasis konsistent sind, aber ein theoretisches Risiko bei künftiger Cross-Plattform-Interop, falls z. B. eine native/Rust-Implementierung dieselben Header jemals eigenständig serialisieren müsste — JSON-Key-Reihenfolge ist in diesem Codebase deterministisch, aber nicht durch einen Standard erzwungen). **Empfehlung (P3):** Auf ein festes Byte-Layout (z. B. `dh(32) || pn(4) || n(4)`) umstellen, sobald eine zweite unabhängige Implementierung (z. B. natives Mobile) geplant ist.
- **Key-Lifetime:** Message-Keys (Double Ratchet) sind Single-Use (nach Gebrauch aus `skipped`-Map gelöscht bzw. nie erneut abgeleitet). Vault-Master-Key ist langlebig (Sitzungsdauer), Vault-KEK wird nur transient während Unlock gehalten.

### HKDF-SHA256 (`@noble/hashes/hkdf`)
- **Verwendete Info-Strings (Domain Separation), vollständige Liste:**
  - `RenkerVault-DoubleRatchet-RK` (Root-Key-Kette im Ratchet)
  - `RenkerVault-X3DH-full-PQ-hybrid` (Handshake MIT One-Time-Prekey)
  - `RenkerVault-X3DH-lite-PQ-hybrid` (Handshake OHNE One-Time-Prekey)
  - `RenkerVault-Vault-MAC` (HMAC-Schlüssel für Vault-Integrität, abgeleitet vom Master-Key)
  - `RenkerVault-SealedSender-Tag` (Sitzungs-Tag für Sealed Sender)
  - **Geprüft:** Alle fünf Strings sind literal paarweise verschieden — keine Kollision, keine Wiederverwendung eines Kontexts für zwei unterschiedliche Zwecke. **Kein Fund.**
- **Fehlendes Element:** Der Symmetric-Ratchet-Schritt (`kdfCk`) nutzt **HMAC direkt**, nicht HKDF (`hmacSha256(ck, [1])`/`hmacSha256(ck, [2])`) — das ist **korrekt und spezifikationskonform** (die offizielle Double-Ratchet-Spezifikation definiert `KDF_CK` explizit als HMAC mit zwei konstanten Bytes, nicht als HKDF) — kein Fund, nur zur Vollständigkeit dokumentiert, damit es nicht fälschlich als Inkonsistenz missverstanden wird.

### Argon2id (`hash-wasm`)
- **Parameter:** `iterations: 4, memorySizeKiB: 65536 (64 MiB), parallelism: 1, hashLength: 32`. Liegt im unteren, aber noch akzeptierten Bereich der OWASP-Empfehlung (OWASP Cheat Sheet empfiehlt je nach Version z. B. m=19MiB/t=2 als striktes Minimum bis m=... für höhere Sicherheit — 64 MiB/t=4 ist oberhalb des Minimums, aber ein bewusster Kompromiss zugunsten der Entsperr-Latenz auf schwächerer Hardware, bereits in SECURITY.md dokumentiert). **Kein neuer Fund**, Parameter sind vertretbar, nicht optimal für Hochsicherheitsszenarien.
- **Salt:** 16 Byte `rand(16)` pro Vault, korrekt einmalig und zufällig. Duress-PIN nutzt einen SEPARATEN Salt (`file.duress.salt`) — korrekt, verhindert Cross-Kontext-Ableitung.
- **Fehlerverhalten:** Kein explizites Try/Catch um `argon2id()` selbst in `deriveKey()` — ein interner WASM-Fehler (z. B. OOM bei 64 MiB auf sehr begrenzten Geräten) würde als ungefangene Exception aus `unlockVault`/`createVault` propagieren. **Kleiner Fund (P3):** kein spezifisches Fehlerhandling für Argon2id-Ausführungsfehler (getrennt von "falsches Passwort"), UI würde vermutlich einen generischen Fehler zeigen statt einer aussagekräftigen Meldung ("Gerät hat nicht genug Speicher für die Entsperrung").

### Double Ratchet — siehe eigener, ausführlicher Abschnitt 3 unten.

### Prekeys / One-Time-Prekeys
- **Erzeugung:** `topUpOneTimePrekeys()` erzeugt neue OTPKs, sobald der lokale Bestand unter `OTPK_LOW_WATERMARK` (15) fällt, bis `OTPK_TARGET` (25), maximal `OTPK_MAX_STORE` (60) lokal gehalten.
- **Server-seitiger Konsum:** `lookup` mit `forHandshake=true` entfernt genau einen OTPK sofort aus `dev.otpks` — **vor** Abschluss des tatsächlichen Handshakes (Finding bereits im letzten Audit dokumentiert, FINDING-011, P3: Erschöpfung durch Lookups ohne Handshake-Abschluss möglich).
- **Kein Ablaufdatum für Prekeys** (weder Signed-Prekey noch OTPK) — es gibt keine automatische Rotation des `prekeyPub`/`pqPrekeyPub` der Identität selbst. Bei Signal rotiert der Signed-Prekey periodisch (z. B. wöchentlich) und wird signiert veröffentlicht. RenkerVault generiert Prekey/PQ-Prekey **einmalig bei Kontoerstellung** und rotiert sie nie automatisch — ein Fund, der im letzten Audit nicht behandelt wurde. **Neuer Fund (P2):** Fehlende periodische Prekey-Rotation verlängert das Zeitfenster, in dem eine Kompromittierung des (langlebigen) Prekey-Private-Keys rückwirkend die Forward Secrecy des Erstkontakt-Handshakes mit JEDEM zukünftigen Kontakt schwächt, bis das Konto neu erstellt wird.
- **Keine Signatur des Signed-Prekeys durch den Identitätsschlüssel** — klassisches X3DH sieht vor, dass der Signed-Prekey vom Identitätsschlüssel signiert wird (`Sig(IK, SPK)`), damit der Empfänger prüfen kann, dass der Prekey tatsächlich vom behaupteten Identitätsinhaber stammt, BEVOR er ihn für einen Handshake nutzt. In RenkerVault gibt es keine solche Signatur — der Prekey wird dem Initiator einfach vom Relay über `lookup()` mitgeliefert und ungeprüft verwendet. Da die Sicherheit letztlich über die X3DH-DH-Berechnung selbst kommt (ein falscher Prekey würde zu einem Shared Secret führen, das der echte Empfänger nicht kennt, also zu einem Fehlschlag der ersten Nachricht), ist das **kein direkter Vertraulichkeitsbruch**, aber es fehlt eine explizite kryptographische Bindung "dieser Prekey gehört nachweislich zu dieser Identität", auf die sich der Client verlassen könnte, OHNE erst eine ganze Nachricht zu riskieren. **Fund (P2):** Prekey-Signatur fehlt (Standard-X3DH-Element).

### Session Establishment (X3DH-Hybrid)
Siehe Kryptografische Analyse oben (HKDF-Domain-Separation) und Abschnitt 0
(Downgrade-Erkennung, FINDING-003). Zusätzlich geprüft in diesem Audit:
**Kein Key-Confirmation-Schritt** getrennt von der ersten Ratchet-Nachricht
— das ist funktional identisch zu Signals eigenem Ansatz (die erste
AEAD-verschlüsselte Nachricht dient selbst als Confirmation, da ihr
Auth-Tag nur mit korrekt abgeleitetem `sk` prüft), also **kein Fund**, nur
zur Vollständigkeit explizit bestätigt.

### Device Authentication
Ed25519-Challenge-Response beim Verbindungsaufbau zum Relay (siehe oben).
**Kein Fund** in der Challenge-Response-Mechanik selbst — die Funde liegen
auf der Ebene "wer darf als Gerät gelten" (Abschnitt 0/1.4), nicht in der
Authentifizierungs-Primitive.

### Safety Numbers (`crypto/safety.ts`)
- **Konstruktion:** 512 Runden SHA-256 über die sortiert-konkatenierten
  X25519-Public-Keys beider Parteien, mit einem festen Domain-Präfix
  (`RenkerVault-SafetyNumber-v1`).
- **Fund (P3, neu in diesem Audit):** 512 SHA-256-Runden ist eine
  unübliche, nicht an einem Standard orientierte Iterationszahl (Signals
  eigenes Verfahren nutzt 5200 Runden SHA-512 pro "Version", mit
  zusätzlicher Einbindung stabiler Nutzer-IDs, nicht nur der Public Keys).
  Das ist **kein Sicherheitsbruch** (Safety Numbers müssen nicht
  brute-force-resistent sein — sie sind für den visuellen Vergleich durch
  Menschen gedacht, nicht als geheimer Wert), aber die Konstruktion
  entspricht keinem etablierten, extern geprüften Verfahren, was bei
  einem externen Audit auffallen würde. **Empfehlung (P3):** Auf ein
  dokumentiertes, etabliertes Verfahren umstellen oder explizit
  begründen, warum die eigene Konstruktion ausreichend ist (aktuell nicht
  begründet).
- Bindet nur an **statische Identitätsschlüssel**, nicht an Geräte — bei
  Multi-Device (sobald implementiert) müsste die Safety Number entweder
  alle Geräte einer Identität erfassen oder es müsste separate
  Per-Geräte-Fingerprints geben (wie bei Signal), sonst verrät eine
  gleichbleibende Safety Number nichts über ein neu hinzugekommenes
  Gerät. **Aktuell nicht relevant**, da es keine Multi-Device-Nutzung über
  die UI gibt (siehe Abschnitt 0) — aber ein Design-Punkt für Phase 6/14.

### Group Encryption
Siehe Abschnitt 7 (Group Cryptography) unten — bereits im letzten Audit
als FINDING-010 dokumentiert (keine Forward Secrecy pro Nachricht
innerhalb einer Epoche, keine Sender-Authentifizierung). Dieser Audit
vertieft das in Abschnitt 7 mit einer expliziten Bewertung einer
MLS-Migration, wie in Phase 4 des Auftrags gefordert.

### Key Rotation
- **Ratchet:** Automatisch bei jedem Antwort-Roundtrip (inhärent im Double-Ratchet-Design). Korrekt.
- **Gruppen-Epoch-Key:** Bei jeder Mitgliederänderung, verifiziert korrekt (siehe letzter Audit).
- **Identitäts-/Prekey-Schlüssel:** **Keine Rotation** — siehe Fund oben (P2).
- **Vault-KEK/Master-Key:** Keine Rotation bei Passphrasenwechsel geprüft — **offene Frage für Phase 5:** Gibt es überhaupt eine "Passphrase ändern"-Funktion? (Grep-Ergebnis: kein `changePassphrase` o. Ä. gefunden — **Fund (P2): Es gibt keine Möglichkeit, die Vault-Passphrase nachträglich zu ändern**, ohne den Tresor komplett neu zu erstellen und alle Daten zu verlieren (`destroyVault` + `createVault`). Das ist sowohl ein Usability- als auch ein Security-Fund: Nutzer, die eine kompromittierte Passphrase vermuten, haben keinen Weg, nur die Passphrase zu rotieren, ohne die gesamte Identität (inkl. aller bestehenden Ratchet-Sitzungen mit Kontakten!) zu verlieren.

### Key Storage
Siehe Abschnitt 5.

### Nonce Generation
Durchgängig `crypto.getRandomValues()` (AES-GCM-IVs, Argon2-Salts,
Ed25519-Server-Nonces, `deviceId`/`msgId`/`userId`-Generierung). **Kein
eigener PRNG, kein Fund.**

### Replay Protection
- **Ratchet-Ebene:** Nach dem letzten Audit korrekt (State wird nur nach
  erfolgreicher Auth committet, ein Replay eines bereits verarbeiteten
  oder bereits-geskippten Message-Keys schlägt sicher fehl, siehe
  FINDING-001-Regressionstests).
- **Relay-Auth-Ebene:** Korrekt (Nonce einmalig, wird nach Verifikation gelöscht).
- **Envelope-Ebene (neu geprüft in diesem Audit):** Es gibt **keine
  Prüfung auf Envelope-Ebene selbst gegen exaktes Wieder-Zustellen
  desselben `msgId`** außerhalb dessen, was der Ratchet ohnehin schon
  über den Message-Counter abfängt. Für `kind: 'reaction'`/`'edit'`/`'delete'`
  (die `targetMsgId` referenzieren) prüft der Client nicht, ob ein
  bestimmtes `targetMsgId` bereits einmal editiert/gelöscht wurde, bevor
  er die Operation erneut anwendet — ein Relay, der eine `edit`-Nachricht
  dupliziert, würde harmlos zweimal denselben (idempotenten) Edit
  anwenden. **Kein Sicherheitsrisiko** (idempotente Operationen), nur zur
  Vollständigkeit geprüft und als unproblematisch bewertet.

---

## 3. Double Ratchet — Vertiefte State-Machine-Analyse (Phase 3)

**Einschätzung zur Kernfrage "Migration auf etablierte Bibliothek vs.
Härtung der bestehenden Implementierung":**

Wie in README.md bereits korrekt dokumentiert: Es gibt aktuell **keine
gepflegte, auditierte Browser-JavaScript-Implementierung** des
Signal-Protokolls (`libsignal-protocol-javascript` ist archiviert;
`@signalapp/libsignal-client` ist ein natives Node-Modul, keine
Browser-/WebView-kompatible Bibliothek ohne zusätzliche Kompilierungs-
/FFI-Arbeit). Eine Migration auf eine "etablierte Bibliothek" ist für den
Browser-/Web-Anteil dieses Projekts **aktuell nicht direkt möglich**, ohne
entweder (a) `@signalapp/libsignal-client` per Tauri-Rust-FFI nur für die
Desktop-Variante einzubinden (würde die Web-/Android-Variante weiterhin
mit der eigenen Komposition zurücklassen — inkonsistente Sicherheits-
niveaus zwischen Plattformen) oder (b) auf eine vollständig neue,
plattformübergreifende Basis zu wechseln (deutlich größerer Umbau).

**Entscheidung dieses Audits (konsistent mit der Bewertung im letzten
Durchgang):** Die bestehende Komposition **härten und testen** statt
"nach Gefühl" reparieren oder blind migrieren. Begründung:

1. Die Primitive selbst (`@noble/curves`, `@noble/post-quantum`,
   WebCrypto AES-GCM, HKDF) sind extern auditierte, etablierte
   Bibliotheken — nur die **Komposition** (wie die Primitive zum
   Double-Ratchet-Protokoll zusammengesetzt werden) ist projekteigen.
2. Der einzige bisher gefundene **kritische** Fehler in dieser Komposition
   (State-Commit vor Auth-Prüfung, FINDING-001) ist behoben und mit 20
   gezielten Regressionstests abgedeckt, die exakt die in Phase 3 dieses
   Auftrags geforderten Szenarien abbilden (Out-of-Order, Packet-Loss,
   Replay, Concurrent-Sends, State-Rollback-Versuche, Session-Restore).
3. Eine Migration auf eine native Bibliothek NUR für Desktop würde einen
   **Downgrade-Vektor** schaffen (Web/Android bleiben bei der eigenen
   Implementierung; ein Angreifer könnte gezielt Web-Clients als
   schwächeres Ziel wählen) — das widerspricht Phase 2, Punkt 5 dieses
   Auftrags ("verhindere Downgrade auf das alte Protokoll").

**Trotzdem bleibt fest:** Diese Komposition ist und bleibt eine
**High-Risk-Komponente im Sinne dieses Audit-Auftrags**, bis ein
**externes** Kryptografie-Audit stattgefunden hat. Interne Tests erhöhen
das Vertrauen, ersetzen aber kein externes Review — das wird in
SECURITY.md, THREAT_MODEL.md und hier wiederholt und deutlich markiert,
nicht nur einmal beiläufig erwähnt.

### Geprüfte Szenarien und ihr aktueller Status

| Szenario | Status | Testabdeckung |
|---|---|---|
| A→B, B→A, A→B→A, viele Nachrichten | ✅ Korrekt | `ratchet.test.ts`, Describe "Grundfluss" (inkl. 1000-Nachrichten-Test, 200-Runden-Alternierung) |
| Out-of-Order (1,3,2 bzw. 1,4,2,3) | ✅ Korrekt | `ratchet.test.ts`, Describe "Out-of-Order-Zustellung" |
| Packet Loss (Nachricht 2 verloren, 1+3+4 empfangen) | ✅ Korrekt | Ebenda, "eine verlorene Nachricht" |
| Replay (gleiche Nachricht mehrfach) | ✅ Korrekt seit FINDING-001-Fix — schlägt sicher fehl, korrumpiert den State nicht | Describe "Replay- und Tamper-Schutz" (6 Tests) |
| Concurrent Sends (A und B "gleichzeitig") | ✅ Korrekt | Describe "Gleichzeitiges Senden / DH-Ratchet" |
| State Corruption (beschädigter State, beschädigte Keys, beschädigte Header) | ✅ Getestet für Header/Ciphertext-Manipulation (Tamper-Tests). **Nicht getestet:** direkt korrumpierter *persistierter* Snapshot (`RatchetSnapshot` mit inkonsistenten Feldern, z. B. `nr` > tatsächlicher Chain-Fortschritt) — siehe neuer Fund unten. |
| Crash Recovery (Absturz zwischen State-Update und Persistierung) | ⚠️ **Nicht spezifisch getestet.** Siehe Analyse unten. |
| Compromise Scenarios (alter/neuer State kompromittiert, Wiederaufnahme) | ⚠️ Teilweise durch Forward-Secrecy-Eigenschaften des Ratchets abgedeckt (jeder DH-Ratchet-Schritt macht alte Chain-Keys für neue Nachrichten irrelevant), aber kein expliziter Test, der einen kompromittierten ALTEN Snapshot gegen einen aktuellen Snapshot vergleicht, um Post-Compromise Security nach einem Ratchet-Schritt zu demonstrieren. |
| Session Termination / Restart | ✅ Getestet (Snapshot → fromSnapshot → weiterer Nachrichtenaustausch) | Describe "Session-Restore / Geräte-Neustart" |
| Device Changes | Siehe Abschnitt 0/1.4 — nicht anwendbar auf Ratchet-Ebene selbst (Ratchet ist pro 1:1-Sitzung, nicht pro Gerät) |

### Neue Funde in diesem Durchgang (Ratchet-spezifisch)

**Fund RATCHET-A (P2): Kein Schutz gegen Persistierung eines
inkonsistenten Snapshots durch einen Prozessabsturz.** `saveRealSessions`
(in `App.tsx`, aufgerufen nach jedem Send/Receive) schreibt den
Ratchet-Snapshot als Teil des gesamten Vault-Zustands via `saveVault()`.
Zwischen einer erfolgreichen `ratchet.decrypt()`/`.encrypt()`-Operation
(die den In-Memory-State bereits verändert hat) und dem tatsächlichen
`saveVault()`-Aufruf liegt eine Zeitspanne, in der ein Prozessabsturz
(Stromausfall, Kill, Crash) dazu führen würde, dass die im UI bereits
angezeigte/gesendete Nachricht NICHT im persistierten Snapshot
widergespiegelt ist. Bei einer gesendeten Nachricht (`encrypt()`): Der
State ist bereits fortgeschritten (`ns` erhöht), aber die alte, noch
nicht persistierte `ns`-Zahl wird nach einem Neustart erneut verwendet —
das bedeutet, ein bereits an den Relay geschickter Ciphertext hätte einen
Message-Key benutzt, der beim NÄCHSTEN Neustart-Send **erneut** aus
demselben (nicht fortgeschrittenen) Chain-Key abgeleitet würde, wenn der
alte, in-memory bereits fortgeschrittene State nicht persistiert wurde,
sondern der Client vom zuletzt GESPEICHERTEN (älteren) Snapshot neu
startet. **Das ist ein potenzielles Message-Key-Wiederverwendungsproblem
bei Crash-Recovery, nicht getestet, nicht gehärtet.** Empfehlung für
Phase 14: `saveVault()` synchron/atomar direkt nach JEDER
State-verändernden Ratchet-Operation erzwingen (nicht gebündelt/verzögert)
und einen Regressionstest schreiben, der einen simulierten Crash zwischen
`encrypt()` und `saveVault()` nachstellt (State-Snapshot vor "Absturz"
sichern, danach prüfen, ob ein erneuter Send denselben Message-Key
produzieren würde wie vor dem Absturz — falls ja: Bug bestätigt und zu
fixen).

**Fund RATCHET-B (P3): `fromSnapshot()` validiert die Eingabe nicht.**
Ein korrupter/manipulierter `RatchetSnapshot` (z. B. aus einem
manipulierten, aber HMAC-technisch noch nicht geprüften Zwischenzustand,
oder ein Programmierfehler an anderer Stelle) wird unkritisch
übernommen — `nr`/`ns`/`pn` könnten z. B. negative oder unsinnig große
Werte enthalten, ohne dass `fromSnapshot()` das zurückweist. Da der
Snapshot Teil des HMAC-geschützten Vault-Inhalts ist, ist eine externe
Manipulation bereits durch die Vault-Integritätsprüfung abgedeckt — dieser
Fund betrifft nur **interne Konsistenz** (ein Bug an anderer Stelle im
Code, der versehentlich einen inkonsistenten Snapshot erzeugt, würde
nicht auffallen). Empfehlung: einfache Sanity-Checks (`nr >= 0`, `ns >= 0`,
`pn >= 0`) in `fromSnapshot()` ergänzen, mit Test.

---

## 4. Group Cryptography (Phase 4 — Ist-Zustand exakt dokumentiert)

**Wie Gruppenkeys entstehen:** `newGroupEpochKey()` (`ratchet.ts`) —
`rand(32)`, ein zufälliger 256-Bit-Schlüssel, unabhängig von jeglichem
Mitgliederschlüssel. Kein KDF, keine Ableitung von Identitätsschlüsseln —
reiner Zufallswert pro Epoche.

**Wie sie verteilt werden:** `distributeGroupKey()` (`App.tsx`) sendet den
aktuellen Epoch-Key **einzeln, pairwise, über die bestehende 1:1-Ratchet-
Sitzung** an jedes Mitglied (`kind: 'group-key'`-Envelope, verschlüsselt
mit dem jeweiligen individuellen Double-Ratchet-Schlüssel dieses
Mitglieds). Kein Broadcast-Mechanismus, kein separates Gruppen-KEM.

**Wie Epochen funktionieren:** `newGroupEpoch(chatId, prevEpoch)` erhöht
den Epoch-Zähler um 1 und generiert einen neuen Zufallsschlüssel.
`applyGroupKey()` beim Empfänger übernimmt Schlüssel+Epoche unkritisch,
sobald eine `group-key`-Nachricht über eine authentifizierte 1:1-Sitzung
ankommt — **keine Prüfung, ob die neue Epoche tatsächlich >
vorherige Epoche ist** (siehe neuer Fund unten).

**Was bei Join passiert:** `handleAddMemberReal` → `rotateRealGroup` →
neue Epoche, neuer Schlüssel, Verteilung an ALLE (alten + neuen)
Mitglieder. Korrekt: der neue Schlüssel garantiert, dass das neue
Mitglied keine ALTEN (vor seinem Beitritt gesendeten) Nachrichten lesen
kann, da es den alten Epoch-Key nie erhält — **Forward Secrecy relativ
zu neuen Mitgliedern besteht.**

**Was bei Leave/Removal passiert:** Analog, `handleRemoveMemberReal` →
`rotateRealGroup` mit der gefilterten Mitgliederliste. Verifiziert
korrekt im letzten Audit — ein entferntes Mitglied bekommt den neuen
Schlüssel nicht und kann folglich keine neuen Nachrichten lesen
(**Post-Compromise Security auf Epochen-Grenze besteht**).

**Was bei Device Removal passiert:** Nicht anwendbar / nicht existent,
da Multi-Device (siehe Abschnitt 0) client-seitig nicht erreichbar ist —
"Device Removal" innerhalb einer Gruppe würde sich aktuell wie eine
normale Mitgliederentfernung verhalten (der gesamte Account, nicht ein
einzelnes Gerät davon, wird aus der Mitgliederliste entfernt).

**Forward Secrecy:** ❌ **Nicht innerhalb einer Epoche.** Alle Nachrichten
einer Epoche nutzen denselben statischen AES-256-GCM-Schlüssel
(`encryptGroup`: `aesGcmEncrypt(g.key, padToTier(plaintext))` — derselbe
`g.key` für jede Nachricht der Epoche, nur der zufällige IV variiert).
Ein einmal kompromittierter Epoch-Key entschlüsselt **jede** Nachricht
dieser Epoche — auch bereits Wochen alte. Epochen-übergreifend besteht
Forward Secrecy (alte Epochen-Keys werden nicht aus neuen abgeleitet,
sind unabhängige Zufallswerte), aber NICHT auf Nachrichtenebene innerhalb
derselben Epoche.

**Post-Compromise Security:** ✅ Auf Epochen-Grenze (nach der nächsten
Rotation ist ein zuvor kompromittierter Key nutzlos), ❌ nicht sofort
(ein Angreifer mit einem kompromittierten aktuellen Epoch-Key liest
JEDE weitere Nachricht mit, bis die App-Logik eine Rotation auslöst — es
gibt keinen automatischen, zeitbasierten Rotations-Trigger, nur
mitgliederänderungsbasiert).

**Welche Nachrichten bei kompromittiertem Epoch-Key entschlüsselt werden
können:** Alle Nachrichten dieser einen Epoche — vorwärts UND rückwärts
in der Zeit, bis zur nächsten Mitgliederänderung.

**Neuer Fund GROUP-A (P1, in diesem Audit entdeckt):** `applyGroupKey()`
prüft **nicht**, ob die eingehende `epoch`-Nummer tatsächlich größer als
die zuletzt bekannte ist:

```ts
applyGroupKey(chatId: string, keyB64: string, epoch: number): string {
  const key = b64.dec(keyB64);
  this.groupKeys.set(chatId, { key, epoch }); // kein Vergleich mit vorherigem epoch!
  return groupFingerprint(key, epoch);
}
```

Ein böswilliges (noch aktives, nicht notwendigerweise entferntes)
Gruppenmitglied — oder ein Angreifer, der eine 1:1-Sitzung mit einem
Gruppenmitglied kompromittiert hat — könnte eine `group-key`-Nachricht
mit einer **älteren** Epochennummer erneut zustellen (Replay einer
früher legitim verschickten `group-key`-Nachricht). Der empfangende
Client würde klaglos auf den älteren, möglicherweise bereits als
kompromittiert bekannten Schlüssel zurückfallen — ein
**Epoch-Rollback-Angriff**, der die Post-Compromise-Security-Eigenschaft
der Gruppen-Rotation direkt untergräbt (das Kernversprechen "nach
Entfernung/Rotation ist der alte Schlüssel nutzlos" gilt dann nicht mehr,
wenn der alte Schlüssel per Replay reaktiviert werden kann). Das ist ein
konkretes Beispiel für genau das, wonach Phase 4 dieses Auftrags fragt
("verhindere alte Epoch-Replays") — **hier fündig geworden.** Fix für
Phase 14: `applyGroupKey` muss `epoch <= this.groupKeys.get(chatId)?.epoch`
verwerfen (monotone Prüfung), mit Regressionstest.

**Bewertung MLS-Migration:** MLS (RFC 9420) würde Forward Secrecy pro
Nachricht (durch eine TreeKEM-Ratchet-Struktur statt eines einzelnen
statischen Epoch-Keys) und kryptographisch verifizierbare
Mitgliedschafts-/Rollenwechsel liefern — das würde FINDING-010 (fehlende
FS pro Nachricht) und den Sender-Authentifizierungs-Fund aus Abschnitt
1.6 strukturell lösen. **Für die aktuelle Architektur nicht direkt
integrierbar:** Es existiert keine reife, für Browser/WebView geeignete
JavaScript-MLS-Implementierung mit vergleichbarem Reifegrad wie die
X3DH/Ratchet-Primitive dieses Projekts (OpenMLS ist eine Rust-Bibliothek,
bräuchte WASM-Kompilierung oder Tauri-FFI — ähnliche Einschränkung wie
bei libsignal). **Empfehlung für Phase 14 (kurzfristig, ohne MLS):**
1. Epoch-Rollback-Schutz (GROUP-A) — klein, kritisch, sofort machbar.
2. Zeitbasierte oder nachrichtenzahl-basierte automatische Epoch-Rotation
   zusätzlich zur mitgliederänderungsbasierten (verkürzt das
   Kompromittierungsfenster innerhalb einer Epoche, löst das
   FS-Problem aber nicht strukturell).
3. Dokumentierte, langfristige Empfehlung: MLS-Migration evaluieren,
   sobald eine Browser-taugliche Implementierung reift, oder wenn die
   Tauri-Desktop-Variante zur primären Plattform wird (dort wäre
   OpenMLS via Rust-FFI realistisch).

---

## 5. Local Vault Hardening (Phase 5 — vertieft)

Bereits im letzten Audit behandelt: Argon2id-Parameter, Salt, MAC-vor-
Decrypt-Reihenfolge, Master-Key-Zeroization, Secure-Delete-Versuch
(FINDING-008/009). **Neue Punkte aus diesem Durchgang:**

- **Atomic Writes:** `localStorage.setItem()` ist pro Aufruf atomar auf
  API-Ebene (kein partiell geschriebener Wert von außen sichtbar), aber
  die Anwendung selbst macht MEHRERE `setItem`-artige Schritte nicht
  als eine Transaktion (siehe RATCHET-A oben — Ratchet-State-Fortschritt
  und `saveVault()` sind zeitlich getrennt). **Bewertet in Abschnitt 3.**
- **Backup Restore:** Es gibt keinen expliziten Export-/Backup-/Restore-
  Mechanismus in der App (kein "Tresor exportieren"-Button gefunden).
  Das bedeutet im Umkehrschluss: Nutzer, die ihr Gerät verlieren, OHNE
  dass ein System-Backup existiert, verlieren ihren gesamten Chatverlauf
  UND ihre Identität unwiederbringlich — das ist eine
  Usability-/Resilienz-Lücke, aber kein Sicherheitsproblem im engeren
  Sinn (im Gegenteil: kein Backup-Mechanismus bedeutet auch keine
  zusätzliche Angriffsfläche durch einen Export-Pfad).
- **Windows DPAPI, macOS Keychain, Linux Secret Service:** DPAPI ist
  umgesetzt (Windows). macOS/Linux-Äquivalente sind weiterhin **nicht
  umgesetzt** (bereits dokumentiert). Dieser Audit bewertet das erneut
  als sinnvolle P2/P3-Erweiterung für Phase 14, kein Blocker.
- **CSP (Tauri):** `tauri.conf.json` hat `"csp": null` — **Fund (P1, neu
  in diesem Audit):** Eine `null`-CSP bedeutet, dass Tauris eingebauter
  CSP-Schutz für das WebView **deaktiviert** ist. Tauri empfiehlt
  ausdrücklich, eine CSP zu setzen, um XSS-Auswirkungen zu begrenzen
  (insbesondere `script-src`, um zu verhindern, dass injizierter Code
  IPC-Commands gegen das Rust-Backend aufrufen könnte — im aktuellen
  Fall besonders relevant, da DPAPI-IPC-Commands existieren, die bei
  erfolgreicher XSS-Ausnutzung missbraucht werden könnten, um den
  gewrappten Master-Key zu manipulieren/zu extrahieren). **Konkrete
  Empfehlung für Phase 14:** CSP explizit setzen (z. B.
  `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`
  — kein `unsafe-eval`, keine externen Quellen, da die App laut README
  ohnehin keine Third-Party-Ressourcen lädt).
- **IPC-Commands (Tauri):** Aktuell nur drei Commands
  (`dpapi_available`, `dpapi_protect`, `dpapi_unprotect`), alle in
  `dpapi.rs`, alle mit minimaler, klar begrenzter Funktion (kein
  generischer Dateisystem- oder Prozesszugriff exponiert). **Kein Fund**
  — die IPC-Oberfläche ist bereits minimal, genau wie Phase 5 es
  verlangt ("minimiere IPC mit Secrets").
- **`capabilities/default.json`:** Nutzt `"core:default"` — die
  Tauri-Standard-Berechtigungen. Nicht auf die drei tatsächlich
  benötigten Custom-Commands eingeschränkt (kein expliziter
  `Capability`-Eintrag für `dpapi_*`, was bei Tauri 2.x bedeutet, dass
  benutzerdefinierte Commands ohne einen registrierten
  `Capability`-Eintrag ggf. NICHT aufrufbar sind, sofern nicht anderweitig
  über das Plugin-System freigegeben — **muss in Phase 14 verifiziert
  werden**, ob die DPAPI-Commands mit der aktuellen Capability-
  Konfiguration überhaupt funktionieren, oder ob das ungetestet in
  einer echten Tauri-GUI bereits stillschweigend bricht. Bereits im
  letzten Audit als "nicht verifizierbar in dieser Umgebung" markiert —
  bleibt offen).
- **Secure-Memory-Garantien, die JavaScript NICHT bieten kann (explizit,
  wie von Phase 5 verlangt):** Kein `mlock()`-Äquivalent (Speicher kann
  jederzeit in die Swap-Datei ausgelagert werden), kein garantiertes
  Überschreiben von Objektspeicher vor der Garbage Collection (V8 kann
  Objekte kopieren/verschieben), keine Kontrolle über
  Compiler-/JIT-Optimierungen, die einen "toten" Zeroization-Schreibzugriff
  wegoptimieren könnten (das `Uint8Array.fill(0)`-Muster aus FINDING-008
  ist die bestmögliche, aber nicht garantierte Annäherung, da es eine
  sichtbare Mutation eines weiterhin referenzierten Objekts ist, was das
  Wegoptimierungsrisiko reduziert, aber nicht auf Null bringt). **Diese
  Grenzen werden in SECURITY.md bereits benannt — dieser Audit bestätigt,
  dass keine der bisherigen Formulierungen "secure deletion" als
  Garantie behauptet (durchsucht: keine solche Übertreibung gefunden).**

---

## 6. Device Pairing — Analyse des Ist-Zustands (Phase 6)

Siehe ausführlich Abschnitt 0. Kurzfassung der Bewertung gegen die
konkreten Prüfpunkte aus dem Auftrag:

| Prüfpunkt | Status |
|---|---|
| Identity Binding | Nicht anwendbar (kein Pairing-Flow) |
| QR-Code-Daten | Safety-Number-QR existiert (Verifikation bestehender Kontakte), kein Pairing-QR |
| Challenge/Response | Existiert für Relay-Auth (Ed25519), nicht für Geräte-Pairing im engeren Sinn |
| Key Confirmation | Nicht anwendbar |
| MITM-Schutz | Nicht anwendbar (siehe Angreifer #14 oben) |
| Replay/Expiration | Nicht anwendbar |
| Device Authorization | Serverseitig korrekt durchgesetzt (`trusted`-Flag, seit FINDING-004/005), aber ohne erreichbaren "neues Gerät hinzufügen"-Flow faktisch nur über die (nicht vorgesehene) Vault-Datei-Kopie erreichbar |
| Device Revocation | Funktioniert (`revoke-device`, serverseitig trust-geprüft) |
| New Device Trust | Serverseitig korrekt NICHT automatisch (`isFirstDevice`-Bootstrap ausgenommen) |
| Server Enforcement | ✅ Bereits vorhanden (letzter Audit) — alle sicherheitskritischen Berechtigungen (`approve-device`, `revoke-device`, Live-Delivery, `lookup()`) sind serverseitig, nicht nur client-seitig geprüft. Erfüllt bereits die explizite Anforderung "Ein neu registriertes Gerät darf niemals allein aufgrund einer Client-seitigen Konvention als vertrauenswürdig gelten." |

**Empfehlung für Phase 14 (siehe auch Abschnitt 8 für einen konkreten
Protokollentwurf):** Bevor die in diesem Auftrag geforderten
Regressionstests ("unauthorized device", "expired pairing", "replayed
pairing", "wrong device", "modified QR data", "revoked device",
"compromised session") sinnvoll geschrieben werden können, muss das
Pairing-Feature selbst existieren. Die serverseitigen Bausteine
(`revoke-device`, Trust-Erzwingung) sind bereits vorhanden und getestet;
was fehlt, ist der Client-Flow, der ein zweites Gerät MIT EIGENEN
Schlüsseln (nicht durch Kopie der Identität!) an ein bestehendes Konto
anhängt und dabei die neue Geräte-`edPub` kryptographisch an die
bestehende Identität bindet.

---

## 7. Relay Server (Phase 7 — Ergänzungen zum letzten Audit)

Bereits behandelt: Auth-Flow, Rate-Limits, Trust-Erzwingung, bounded
Storage (FINDING-004 bis 007, 011, 012). Neu in diesem Durchgang geprüft:

- **Origin Validation:** Der `WebSocketServer` (`ws`-Bibliothek) prüft
  aktuell **keinen** `Origin`-Header beim Verbindungsaufbau (`wss.on('connection', ...)`
  nimmt jede Verbindung unabhängig vom Origin-Header an). Für eine
  Desktop-/Mobile-App ist das im Kern unproblematisch (kein
  Same-Origin-Kontext wie im Browser), aber für den **Web-Client** im
  Browser bedeutet das: jede beliebige Website könnte theoretisch aus
  dem Browser eines Opfers heraus eine WebSocket-Verbindung zum selben
  Relay aufbauen (WebSocket ist NICHT durch CORS/SOP beschränkt wie
  `fetch`/XHR). Das allein ist noch kein Bruch (der Angreifer bräuchte
  weiterhin gültige Anmeldedaten/Signaturen für ein Konto, um irgendetwas
  Sinnvolles zu tun), aber es entzieht dem Server eine kostenlose,
  zusätzliche Verteidigungsebene gegen browserbasierte Command-and-
  Control-artige Nutzung des Relays durch bösartige Drittseiten (z. B.
  massenhaftes anonymes Ausprobieren von `lookup`-Anfragen zur
  User-Enumeration von einer beliebigen Website aus, im Namen des
  Browser-Opfers, aber ohne dessen Zustimmung). **Fund (P2, neu):**
  fehlende Origin-Prüfung für Browser-Clients.
- **User Enumeration:** `lookup` liefert `found: true/false` unmittelbar
  zurück — ein Angreifer kann durch systematisches Durchprobieren von
  `userId`-Werten (`RV-XXXX-XXXX`, 32 Bit Effektiventropie) feststellen,
  welche Konten existieren. Rate-Limitierung existiert (`OTPK_LOOKUP_RATE_LIMIT`
  für `forHandshake:true`-Lookups), aber **normale** Lookups
  (`forHandshake:false`, z. B. reine Namens-/Präsenzabfragen) sind NICHT
  separat ratenbegrenzt — nur implizit über das generische
  Pro-Socket-Nachrichtenlimit (30/s). Bei 30 Lookups/Sekunde ließe sich
  der 32-Bit-`userId`-Raum (4,3 Milliarden) zwar nicht in praktikabler
  Zeit von einem einzelnen Socket durchsuchen (~4,5 Jahre bei 30/s), aber
  mit mehreren parallelen Verbindungen (nur durch `MAX_CONNS_PER_IP=20`
  begrenzt, nicht global) deutlich beschleunigbar. **Fund (P2, neu):**
  kein dediziertes Rate-Limit für normale (nicht-Handshake) Lookups,
  User-Enumeration dadurch beschleunigbar.
- **Timing Leakage:** `guard()`/`recordAuthFail()` laufen für
  existierende wie nicht-existierende `userId`s strukturell gleich ab
  (`getUser()` legt bei Bedarf transparent einen leeren Eintrag an) —
  **kein Timing-Unterschied zwischen "Konto existiert nicht" und "Konto
  existiert, aber falsche Signatur" gefunden**, das ist positiv (verhindert
  Konto-Existenz-Timing-Oracle über den Auth-Pfad).
- **Error Messages:** Alle Fehlerantworten (`{type:'error', error: '...'}`)
  nutzen kurze, generische Codes (`bad-hello`, `key-mismatch`,
  `not-trusted`, `rate-limited` etc.) ohne interne Details (Stack-Traces,
  interne IDs) — **kein Fund**, sauber.
- **Message Size Limits:** `MAX_MSG_BYTES = 2 MiB` via `WebSocketServer`-
  `maxPayload`-Option — von der `ws`-Bibliothek selbst durchgesetzt
  (Verbindung wird bei Überschreitung serverseitig geschlossen), **korrekt**.
- **Connection Handling:** `AUTH_TIMEOUT_MS` (15s) schließt unauthentifizierte
  Verbindungen automatisch — **korrekt**, verhindert Slowloris-artiges
  Offenhalten unauthentifizierter Sockets.

---

## 8. Metadata Privacy (Phase 8 — Referenz)

Vollständig bereits in [docs/METADATA.md](docs/METADATA.md) (feldweise
Analyse) und [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (Was Relay/Tor/
Cover-Traffic/PQ schützen) dokumentiert. Keine neuen Funde in diesem
Durchgang über die dort bereits benannten hinaus (größter offener Punkt:
`replyTo.preview` und `fromName` liegen weiterhin im Klartext-Envelope,
nicht in der verschlüsselten Payload — bereits als priorisierte Empfehlung
in METADATA.md festgehalten).

---

## 9. Entwurf: QR-basiertes Device-Provisioning-Protokoll (für Phase 14)

Da Device-Pairing als Feature fehlt (Abschnitt 0/6), hier ein konkreter,
an Signals Device-Linking angelehnter Entwurf, der bei Umsetzung in
Phase 14 MITM-resistent und ohne Schlüsselaustausch über den
(potenziell bösartigen) Relay auskommt:

1. **Primärgerät** (bereits eingeloggt) zeigt einen QR-Code mit: der
   eigenen `userId`, einem frischen, kurzlebigen X25519-Ephemeral-Public-Key
   und einem zufälligen 128-Bit-Provisioning-Nonce.
2. **Neues Gerät** scannt den QR-Code (Kanalbindung: der QR-Code selbst
   ist der vertrauenswürdige Out-of-Band-Kanal, kein Relay involviert),
   generiert sein EIGENES vollständiges Schlüsselbündel lokal (NICHT
   die Identität des Primärgeräts kopieren — jedes Gerät behält eigene
   private Schlüssel, wie bei Signal), und verschlüsselt sein neues
   `edPub`/`xPub`/Geräte-Metadaten mit einem aus dem gescannten
   Ephemeral-Key + eigenem Ephemeral-Key abgeleiteten Shared Secret
   (ECDH), signiert zusätzlich mit dem eigenen neuen `edPriv`.
3. Diese verschlüsselte Provisioning-Nachricht wird über den Relay an
   das Primärgerät geschickt (der Relay sieht nur Ciphertext, wie bei
   jeder anderen Nachricht auch).
4. **Primärgerät** entschlüsselt, zeigt dem Nutzer die Geräte-Metadaten
   (Name, Typ) zur Bestätigung, UND einen aus dem Ephemeral-Shared-Secret
   abgeleiteten kurzen Bestätigungscode — der MUSS mit einem auf dem
   NEUEN Gerät angezeigten identischen Code übereinstimmen (analog zu
   Bluetooth-Pairing-Codes). Erst nach dieser doppelten Bestätigung
   (Nutzer bestätigt auf BEIDEN Geräten) sendet das Primärgerät
   `approve-device` an den Relay.
5. **Expiration:** Das Provisioning-Nonce/der QR-Code ist nur 2 Minuten
   gültig; abgelaufene Provisioning-Versuche werden vom Primärgerät
   verworfen (client-seitige Prüfung reicht hier, da ein abgelaufener
   Versuch ohnehin nie zu einem `approve-device` führt).

Damit wäre MITM während Pairing strukturell ausgeschlossen (der
QR-Code-Scan selbst ist der Vertrauensanker, nicht der Relay), und
`approve-device` würde erst nach einer ECHTEN, doppelt bestätigten
Geräte-Identifikation ausgelöst — nicht mehr durch einen bloßen Klick auf
eine Geräteliste, die ein Nutzer bei Unachtsamkeit falsch interpretieren
könnte (Abschnitt 1.4-Restrisiko).

---

## 10. Priorisierte Fund-Übersicht (Ausgangspunkt für Phase 14)

| ID | Severity | Kurzbeschreibung | Neu in diesem Audit? |
|---|---|---|---|
| GROUP-A | **P1** | Gruppen-Epoch-Rollback: `applyGroupKey` prüft Epoche nicht monoton, Replay einer alten `group-key`-Nachricht reaktiviert einen alten (potenziell kompromittierten) Schlüssel | ✅ Ja |
| VAULT-CSP | **P1** | Tauri-CSP ist `null` — WebView-XSS-Schutz deaktiviert, insbesondere riskant wegen vorhandener DPAPI-IPC-Commands | ✅ Ja |
| RATCHET-A | **P2** | Kein Schutz gegen inkonsistente Ratchet-State-Persistierung bei Prozessabsturz zwischen State-Update und `saveVault()` | ✅ Ja |
| PREKEY-ROTATE | **P2** | Keine automatische Rotation von Identitäts-Prekey/PQ-Prekey | ✅ Ja |
| PREKEY-SIG | **P2** | Signed-Prekey ist nicht durch den Identitätsschlüssel signiert (klassisches X3DH-Element fehlt) | ✅ Ja |
| PASSPHRASE-ROTATE | **P2** | Keine Möglichkeit, die Vault-Passphrase zu ändern, ohne die gesamte Identität zu verlieren | ✅ Ja |
| RELAY-ORIGIN | **P2** | Keine `Origin`-Header-Prüfung, WebSocket ist nicht CORS-beschränkt | ✅ Ja |
| RELAY-ENUM | **P2** | Kein dediziertes Rate-Limit für normale (nicht-Handshake) `lookup`-Aufrufe — User-Enumeration beschleunigbar | ✅ Ja |
| STORAGE-ROLLBACK | **P2** | Kein Generation-Counter im Vault-Format — Rollback auf eine ältere, aber gültige Vault-Version unentdeckt | ✅ Ja |
| RATCHET-B | **P3** | `fromSnapshot()` validiert Eingabewerte nicht (Sanity-Checks fehlen) | ✅ Ja |
| SAFETY-NUM | **P3** | Safety-Number-Konstruktion (512×SHA-256) folgt keinem etablierten Standard | ✅ Ja |
| AAD-ENCODING | **P3** | Ratchet-AAD nutzt `JSON.stringify` statt festem Byte-Layout (Fragilität bei künftiger Cross-Plattform-Interop) | ✅ Ja |
| ARGON2-ERR | **P3** | Kein spezifisches Fehlerhandling für Argon2id-Ausführungsfehler (getrennt von "falsches Passwort") | ✅ Ja |
| DEVICE-PAIRING | **P2** (Feature-Lücke, kein Bug) | Kein Client-Flow für "neues Gerät zu bestehendem Konto hinzufügen" — macht Phase 6 gegenstandslos, bis gebaut | ✅ Ja |
| CI-FEHLT | **P2** | Keine CI-Pipeline (`.github/workflows` existiert nicht) — kein automatisierter `npm audit`/Test/Build-Check bei PRs | ✅ Ja |
| SBOM-FEHLT | **P3** | Kein SBOM, keine Artifact Attestation, keine Code-Signatur (teils bereits in SECURITY.md dokumentiert) | Teilweise bekannt, hier vertieft |
| FINDING-001 bis 012 | (siehe docs/FINDINGS.md) | Alle bereits behoben bzw. dokumentiert im letzten Audit | Nein (Referenz) |

**P0 (kritisch):** In diesem Durchgang **keine neuen P0-Funde** — die
beiden P0-Bugs aus dem letzten Audit (Ratchet-State-Corruption,
Relay-Trust-Bypass) sind bereits behoben und getestet. Das ist ein
positives Ergebnis, kein Grund zur Nachlässigkeit — GROUP-A und
VAULT-CSP sind P1 und sollten vorrangig behandelt werden.

---

## Zusammenfassung für Phase 14

Priorität für die Implementierungsphase, wie vom Auftrag verlangt:

- **P0:** Keine offen.
- **P1:** GROUP-A (Epoch-Rollback-Schutz), VAULT-CSP (Tauri-CSP setzen).
- **P2:** RATCHET-A, PREKEY-ROTATE, PREKEY-SIG, PASSPHRASE-ROTATE,
  RELAY-ORIGIN, RELAY-ENUM, STORAGE-ROLLBACK, DEVICE-PAIRING (Feature),
  CI-FEHLT.
- **P3:** RATCHET-B, SAFETY-NUM, AAD-ENCODING, ARGON2-ERR, SBOM-FEHLT.
- **P4 (Developer Experience):** CI-Pipeline-Ausbau über reine
  Security-Checks hinaus, Fuzzing-Infrastruktur (Phase 11), SBOM-Tooling.

Kein Code wurde in dieser Phase verändert. Implementierung folgt in
Phase 14 nach Rückmeldung/Freigabe dieser Analyse.
