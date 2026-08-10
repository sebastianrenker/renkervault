# THREAT_MODEL.md — Was RenkerVault schützt und was nicht

Dieses Dokument ist die ehrliche Gegenstück-Seite zu [SECURITY.md](../SECURITY.md):
statt "was wurde gebaut" beantwortet es konkret "wovor schützt das tatsächlich,
und wovor nicht". Stand: nach dem Security-Hardening-Audit vom 10.08.2026
(siehe [FINDINGS.md](FINDINGS.md) für die Einzelbefunde dieses Audits).

## Angreifermodelle

| # | Angreifer | Fähigkeiten |
|---|---|---|
| A1 | Passiver Netzwerk-Beobachter | Sieht TLS-verschlüsselten Traffic zum Relay, kennt IP-Adressen und Timing |
| A2 | Bösartiger/kompromittierter Relay-Betreiber | Sieht alles, was der Relay-Prozess sieht (siehe Tabelle unten), kann Nachrichten verzögern/duplizieren/verwerfen, aber NICHT E2E-Ciphertext entschlüsseln |
| A3 | Angreifer mit Kenntnis der userId eines Opfers | userIds sind bewusst teilbar (wie ein Kontaktname), also kein Geheimnis — siehe FINDING-006 |
| A4 | Kompromittiertes Endgerät (Malware/Keylogger/physischer Zugriff im entsperrten Zustand) | Sieht alles, was die App im Klartext im Speicher hat |
| A5 | Ein aktuelles Gruppenmitglied | Besitzt den aktuellen Epoch-Key der Gruppe |
| A6 | Zukünftiger Quantenangreifer ("Harvest now, decrypt later") | Zeichnet heute Ciphertext auf, entschlüsselt in geschätzt 10+ Jahren mit einem kryptographisch relevanten Quantencomputer |

## Was der Relay sieht (A2)

| Sichtbar für den Relay-Betreiber | NICHT sichtbar |
|---|---|
| Konto-ID des Absenders beim allerersten Kontakt (X3DH-Envelope) | Nachrichteninhalt (immer, ausnahmslos Ciphertext) |
| Konto-ID des Empfängers (`to`-Feld, zwingend fürs Routing) | Absender-Konto-ID bei 1:1-Folgenachrichten (Sealed Sender, Abschnitt 3a in SECURITY.md) |
| Zeitpunkt und Häufigkeit von Verbindungen/Sends (Timing) | Exakte Klartextlänge (Padding auf 9 Stufen, Abschnitt 4g) |
| Envelope-Größe (eine von 9 Padding-Stufen, nicht die exakte Länge) | Ob eine Nachricht "echt" oder Cover-Traffic ist (Marker liegt in der verschlüsselten Payload) |
| IP-Adresse (außer bei Tor-Hidden-Service-Betrieb) | Gruppenmitgliederliste (liegt nur in der verschlüsselten Payload) |
| Geräte-Metadaten (Anzahl, Namen, Online-Status, Vertrauensstatus) | Dateinamen/-typen (seit Padding-Update: Byte-Länge der Payload inkl. Metadaten-JSON ist gepolstert, nicht mehr direkt proportional zur Rohdatei) |
| Anzahl+Timing der `send`-Aufrufe pro Konto | Wer mit wem eine Gruppenkonversation führt (Gruppen-Chat-ID ist zufällig, keine Klartext-Mitgliederliste im Envelope) |

**Wichtig, neu durch dieses Audit korrigiert:** Bis zu diesem Update konnte ein
*technisch unbestätigtes* Geräte-Add für ein beliebiges Konto (sofern die
userId bekannt ist) sich selbst freischalten und live jede eingehende
Nachricht des Kontos mitlesen (Envelope-Metadaten UND — nach Abschluss eines
eigenen Handshakes — auch Ciphertext, das aber ohne die echten Vault-Schlüssel
des Opfers weiterhin nicht entschlüsselbar wäre). Das war ein Fehler im
Server-seitigen Trust-Modell, kein akzeptierter Kompromiss — siehe
FINDING-004/FINDING-005 in [FINDINGS.md](FINDINGS.md). Behoben.

## Was ein kompromittiertes Endgerät sieht (A4)

Vollständig alles: entschlüsselte Nachrichten im UI, den entsperrten
Master-Key im Prozessspeicher (solange der Vault entsperrt ist), jede
Eingabe (Keylogger), Zwischenablage. **Keine E2E-Verschlüsselung kann das
verhindern** — das ist keine RenkerVault-spezifische Grenze, sondern gilt für
jede Software, die auf einem kompromittierten Gerät läuft.

Nach dem Sperren (`lockVault()`) wird der Master-Key im JS-Heap mit Nullen
überschrieben, bevor die Referenz fällt (siehe FINDING-008) — das verkürzt
das Zeitfenster für einen Memory-Dump, garantiert aber NICHT die vollständige
Entfernung: V8s Garbage Collector und die interne WebCrypto-Implementierung
können eigene, aus JS nicht erreichbare Kopien halten. Ein Angreifer mit
Vollzugriff auf ein *entsperrtes* Gerät gewinnt ohnehin nichts durch diese
Härtung — sie wirkt ausschließlich für den Zeitraum NACH dem Sperren.

## Was Tor schützt — und was nicht

**Schützt:** Die IP-Adresse des Nutzers gegenüber dem Relay-Betreiber UND
gegenüber jedem Netzwerk-Beobachter zwischen Nutzer und Relay (bei Betrieb
als `.onion`-Hidden-Service, siehe `deploy/torrc.snippet`). Ohne Tor sieht
der Relay-Betreiber immer die echte IP.

**Schützt NICHT:** Vor Endpunkt-Korrelation durch den Relay-Betreiber selbst
(er sieht ja ohnehin, welches authentifizierte Konto wann sendet — Tor
verbirgt nur die IP, nicht die Konto-ID). Schützt nicht vor Timing-Analyse
zwischen zwei Nutzern, die BEIDE über denselben Relay laufen (globaler
Passiv-Beobachter mit Sicht auf den gesamten Relay-Traffic könnte
Sende-/Empfangszeitpunkte korrelieren — Cover-Traffic mildert das, beseitigt
es aber nicht vollständig, siehe unten). Schützt nicht vor
Endgerät-Kompromittierung (A4).

## Was Cover-Traffic schützt — und was nicht

**Schützt:** Verschleiert (statistisch, nicht kryptographisch beweisbar),
*wann genau* echte Kommunikation stattfindet, indem Dummy-Nachrichten in
plausibler Frequenz/Größe dazwischengemischt werden, ununterscheidbar vom
Relay aus (Marker liegt in der verschlüsselten Payload, siehe Abschnitt 4g in
SECURITY.md).

**Schützt NICHT:** Die Tatsache, dass überhaupt eine authentifizierte
WebSocket-Verbindung zum Relay besteht (das ist bei jedem Client-Server-Modell
sichtbar). Schützt nicht bei sehr wenigen Kontakten (statistische
Verschleierung ist bei 1-2 Kontakten deutlich schwächer als bei 20). Ist
KEIN Ersatz für ein Mixnet — ein Angreifer mit globaler Sicht auf den
gesamten Relay-Traffic UND ausreichend Rechenzeit für statistische Analyse
über viele Tage könnte echte von Cover-Traffic-Mustern ggf. noch
unterscheiden. Kostet dauerhaft etwas Bandbreite/Akku.

## Was Post-Quantum-Hybrid (ML-KEM-768) schützt — und was nicht

Genauer als SECURITY.md Abschnitt 4b, mit der vom Audit geforderten Trennung:

| Komponente | PQ-geschützt? |
|---|---|
| X3DH-Erstkontakt-Handshake (Shared Secret für Sitzungsaufbau) | ✅ Ja — X25519 + ML-KEM-768 hybrid, HKDF-gemischt |
| Double-Ratchet-Schritte danach (jede weitere DH-Ratchet-Runde) | ❌ Nein — reines X25519, wie bei Signal auch |
| Identitäts-Authentifizierung (wer ist mein Gesprächspartner) | ❌ Nein — Ed25519-Signaturen (klassisch), kein PQ-Signaturverfahren im Einsatz |
| Vault-Verschlüsselung (Argon2id/AES-256-GCM) | Nicht zutreffend — AES-256 gilt bereits als PQ-resistent (Grover liefert nur quadratische statt exponentielle Beschleunigung), kein KEM/ECC involviert |

**Downgrade-Resistenz (neu durch dieses Audit geprüft):** X3DH kann mit oder
ohne One-Time-Prekey ablaufen ("full" vs. "lite", per HKDF-Domain-Separation
getrennt — siehe `crypto/ratchet.ts`). Ein böswilliger Relay könnte
grundsätzlich jeden Handshake stillschweigend auf "lite" herunterstufen,
indem er beim Lookup nie einen verfügbaren One-Time-Prekey ausliefert — dafür
gibt es aktuell nur eine heuristische Erkennung (FINDING-003: Warnung, wenn
ein eingehender Handshake ohne OTPK ankommt, obwohl eigene OTPKs verfügbar
sind), keinen kryptographischen Downgrade-Schutz. Das ML-KEM-Element selbst
ist von dieser Downgrade-Frage unberührt (es ist in beiden Modi immer
enthalten, unabhängig vom OTPK).

## Gruppenverschlüsselung — ehrliche Grenzen (aus diesem Audit)

Verifiziert: Mitgliederänderungen (Hinzufügen/Entfernen) lösen korrekt eine
neue Schlüssel-Epoche aus, die an die verbleibenden Mitglieder neu verteilt
wird (`ui/App.tsx`: `rotateRealGroup`) — ein entferntes Mitglied kann
nachfolgende Nachrichten tatsächlich nicht mehr lesen (Post-Compromise
Security auf Epochen-Grenze).

**Was NICHT gegeben ist**, verglichen mit einer etablierten Konstruktion wie
Signals Sender-Keys oder MLS:

- **Keine Forward Secrecy innerhalb einer Epoche.** Alle Nachrichten einer
  Epoche nutzen denselben statischen AES-256-GCM-Schlüssel. Wird dieser
  Schlüssel einmal kompromittiert (z. B. durch ein kompromittiertes
  Mitglieder-Gerät), sind ALLE Nachrichten dieser Epoche rückwirkend lesbar —
  nicht nur zukünftige. Der 1:1-Chat hat diese Schwäche nicht (jede Nachricht
  eigener Ratchet-Message-Key).
- **Keine kryptographische Absender-Authentifizierung innerhalb der Gruppe.**
  Der Gruppenschlüssel ist symmetrisch und wird von allen Mitgliedern
  geteilt — jedes Mitglied könnte technisch eine Nachricht verschlüsseln, die
  im Client als "von Person X" angezeigt wird, ohne dass eine Signatur das
  belegt (`fromName` ist Envelope-Metadatenfeld, keine signierte Behauptung).
  Signals Sender-Keys lösen das über einen separaten Signatur-Schlüssel pro
  Mitglied — hier nicht vorhanden.
- **Kein Schutz gegen ein aktuelles, böswilliges Mitglied, das den
  Gruppenschlüssel außerhalb der App weitergibt** (z. B. an ein bereits
  entferntes Mitglied) — inhärent bei jedem geteilten symmetrischen Schlüssel,
  nicht RenkerVault-spezifisch lösbar ohne ein Sender-Keys/MLS-Modell.

**Empfehlung für echten Gruppeneinsatz mit mehr als "Bekanntenkreis"-Vertrauen:**
Migration auf eine etablierte Gruppen-Konstruktion (Signal Sender Keys oder
IETF MLS/RFC 9420) statt der aktuellen "ein Epoch-Key für alle"-Lösung. Das
ist ein eigenständiges, mehrwöchiges Architekturprojekt (neues
Schlüsselverteilungs-Protokoll, pro-Mitglied-Ratchet-Ketten,
Client-seitige Gruppenzustandsverwaltung) und wurde in diesem Audit bewusst
NICHT im Schnellverfahren nachgebaut, um keine unauditierte Kryptografie
"schnell" einzuführen. Bis dahin: **Gruppen in RenkerVault sind für kleine,
gegenseitig vertrauende Gruppen geeignet, nicht für Szenarien, in denen ein
Mitglied selbst potenziell böswillig sein könnte.**

## Auditierte vs. nicht auditierte Teile

| Teil | Status |
|---|---|
| Kryptografische Primitive (`@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, `hash-wasm`, WebCrypto AES-GCM) | ✅ Extern auditierte, etablierte Bibliotheken — keine Eigenimplementierung |
| Protokoll-Komposition (Double Ratchet, X3DH-Hybrid in `crypto/ratchet.ts`) | ⚠️ Internes Hardening-Audit 10.08.2026 (dieses Dokument + FINDINGS.md) — KEIN externes Krypto-Audit durch Dritte |
| Relay-Protokoll (`server/src/index.js`) | ⚠️ Internes Hardening-Audit 10.08.2026, echte Integrationstests gegen den laufenden Prozess — KEIN externer Pen-Test |
| Vault/Storage (`crypto/vault.ts`) | ⚠️ Internes Hardening-Audit — KEIN externes Audit |
| Gruppenverschlüsselung | ⚠️ Bekanntermaßen unzureichend für Hochsicherheits-Gruppenszenarien (siehe oben) — keine Migration in diesem Audit |
| DPAPI-Hardware-Bindung (Windows) | ✅ Native Ebene per `cargo test` verifiziert; vollständiger In-App-Rundlauf nicht in dieser Umgebung testbar |

Vor einem echten Produktiveinsatz mit relevantem Bedrohungsmodell (siehe
README "Hintergrund") bleibt ein **externes Kryptografie-Audit durch
Dritte** die wichtigste offene Maßnahme — ein internes Audit, egal wie
gründlich, ersetzt das nicht.
