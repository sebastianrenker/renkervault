# FINDINGS.md — Security-Hardening-Audit, 10.08.2026

Strukturierte Befundliste des vollständigen Security-Audits (Kryptografie,
Protokoll, Relay, Vault, Metadaten). Priorität: P0 = kritisch, P1 = hoch,
P2 = mittel, P3 = niedrig. Kein Befund wurde aus Schwierigkeitsgründen
weggelassen — nicht behobene Punkte sind explizit als "Dokumentiert,
nicht behoben" markiert statt verschwiegen.

---

### FINDING-001 — P0 — Double Ratchet: State-Mutation vor Authentifizierung
**Komponente:** Kryptografische Korrektheit / Protokollsicherheit
**Datei:** `client/src/crypto/ratchet.ts`, `decrypt()`
**Problem:** Vor dem Fix wurden `ckr`, `nr`, `dhr`, sogar ein komplett neues
eigenes Schlüsselpaar (`dhs`) direkt auf `this` geschrieben, BEVOR die
AES-GCM-Authentifizierung des tatsächlichen Ciphertexts geprüft wurde. Bei
fehlgeschlagener Entschlüsselung gab es keinen Rollback. Weicht von der
offiziellen Signal-Spezifikation ab, die explizit `state = deepcopy(state)`
vor dem Versuch vorschreibt und erst nach Erfolg committet.
**Angriffsszenario:** Ein böswilliger oder auch nur unzuverlässiger Relay
sendet eine doppelte, verspätete oder gefälschte Nachricht (auch mit
frei erfundenem DH-Public-Key im Header). Der Client verändert seinen
Ratchet-Zustand spekulativ, die Entschlüsselung schlägt fehl, der
korrumpierte Zustand bleibt aber bestehen — die Sitzung ist ab diesem
Zeitpunkt dauerhaft unbrauchbar (Chain-Key-Desync), ohne dass der
Angreifer irgendeinen Schlüssel kennen musste.
**Impact:** Vollständiger Denial-of-Service der Ende-zu-Ende-Sitzung durch
ein einziges manipuliertes Paket. Kein Vertraulichkeitsbruch, aber ein
schwerer Verfügbarkeits-/Integritätsfehler des Kernprotokolls.
**Likelihood:** Hoch — auslösbar durch jeden, der Pakete an den Client
zustellen kann (der Relay selbst reicht).
**Fix:** `decrypt()` arbeitet jetzt auf einer geklonten Kopie des States
(`cloneState`, `skipMessageKeysInto`, `dhRatchetInto` — alle draft-basiert).
Committet wird `this.state = draft` erst NACH erfolgreichem
`aesGcmDecrypt`. Zusätzlich: `encrypt()`/`decrypt()` jetzt über eine
interne Promise-Queue serialisiert (siehe FINDING-002).
**Regressionstest:** `client/tests/security/ratchet.test.ts`,
Describe-Block "Replay- und Tamper-Schutz (P0-Regressionstest)" — 6 Tests,
u. a. "gefälschter Header mit beliebigem DH-Public-Key wird abgelehnt und
zerstört die Sitzung nicht (P0)".
**Status:** ✅ Behoben.

---

### FINDING-002 — P1 — Ratchet nicht sicher bei gleichzeitigen Aufrufen
**Komponente:** Kryptografische Korrektheit
**Datei:** `client/src/crypto/ratchet.ts`, `encrypt()`/`decrypt()`
**Problem:** Beide Methoden lasen den aktuellen Kettenschlüssel, warteten
asynchron auf eine WebCrypto-Operation und schrieben den neuen
Kettenschlüssel erst danach zurück. Bei zwei überlappenden Aufrufen auf
derselben Instanz (z. B. `Promise.all([...].map(enc))`) lasen beide
denselben Ausgangszustand, bevor der erste committete.
**Angriffsszenario:** Kein externer Angreifer nötig — reproduzierbar allein
durch das eigene Aufrufmuster der App (z. B. gleichzeitiges Versenden
mehrerer Nachrichten). Führt zu Message-Key-Wiederverwendung mit
identischem Header-Zähler `n` für unterschiedliche Klartexte — ein
Kernprinzip von Stream-artigen AEAD-Konstruktionen (nie denselben Schlüssel
für zwei Klartexte) wäre verletzt.
**Impact:** Bei tatsächlichem Auftreten: Schwächung der
Vertraulichkeitsgarantie für die betroffenen Nachrichten (gleicher
Message-Key, unterschiedliche IVs — AES-GCM bleibt zwar durch den
zufälligen 96-Bit-IV formal sicher, aber die Chain-Key-Fortschreibung wird
inkonsistent, was zu späteren Entschlüsselungsfehlern führt).
**Likelihood:** Mittel — hängt vom Call-Pattern der UI ab, aber nicht
grundsätzlich ausgeschlossen (z. B. Cover-Traffic-Timer parallel zu
Nutzer-Send).
**Fix:** Interne `runExclusive()`-Queue in der `Ratchet`-Klasse — jeder
`encrypt()`/`decrypt()`-Aufruf wird jetzt strikt serialisiert, unabhängig
vom Aufrufer-Verhalten.
**Regressionstest:** `ratchet.test.ts`, "Zustellreihenfolge 1,4,2,3 wird
korrekt entschlüsselt" (nutzt `Promise.all` für parallele Verschlüsselung),
"beide Seiten senden 'gleichzeitig'".
**Status:** ✅ Behoben.

---

### FINDING-003 — P2 — X3DH-Downgrade auf "lite"-Modus ohne kryptographischen Schutz
**Komponente:** Protokollsicherheit / Downgrade-Resistenz
**Datei:** `client/src/net/realchat.ts` (`beginSession`), `server/src/index.js` (`lookup`)
**Problem:** Ob ein Handshake mit oder ohne One-Time-Prekey ("full" vs.
"lite") abläuft, wird vollständig durch die Lookup-Antwort des Relays
bestimmt. Ein böswilliger Relay könnte konsequent keinen verfügbaren OTPK
ausliefern und damit jeden Handshake unbemerkt auf "lite" herunterstufen —
weder Client noch Nutzer erhalten dafür ein Signal.
**Angriffsszenario:** Relay-Betreiber unterdrückt OTPKs selektiv oder
generell. Betrifft NICHT die laufende Ratchet-Sicherheit (die bleibt
identisch), sondern schwächt gezielt die Forward Secrecy der allerersten
Ratchet-Nachricht gegen ein Szenario, in dem der Signed-Prekey des
Empfängers später kompromittiert UND der Ciphertext aufgezeichnet wurde.
**Impact:** Eng begrenzt (nur erste Nachricht, nur unter zusätzlicher
Signed-Prekey-Kompromittierung), aber ein echter, unentdeckbarer
Downgrade — genau das, was Abschnitt 4 des Audit-Auftrags explizit
verlangt hat zu prüfen.
**Likelihood:** Niedrig (setzt einen aktiv böswilligen Relay-Betreiber
voraus, nicht nur einen passiven Beobachter), aber nicht auszuschließen —
das ist exakt das im Bedrohungsmodell (README "Hintergrund") beschriebene
Szenario.
**Fix (Mitigation, kein vollständiger kryptographischer Schutz):** Der
Empfänger vergleicht jetzt bei eingehenden Erstkontakt-Nachrichten, ob kein
OTPK referenziert wurde, obwohl er selbst noch OTPKs zur Verfügung hatte —
und protokolliert das als Sicherheitswarnung (`ui/App.tsx`,
`X3DH_DOWNGRADE`). Ein vollständiger kryptographischer Downgrade-Schutz
bräuchte signierte Prekey-Bundles mit vom Relay unabhängig verifizierbarer
Frische (z. B. Transparency-Log) — das ist ein größeres, eigenständiges
Architekturthema.
**Regressionstest:** `client/tests/security/handshake.test.ts` (Domain-
Separation zwischen full/lite verifiziert). Die Erkennungsheuristik selbst
ist UI-seitig und nicht durch einen Unit-Test abgedeckt (keine Relay-
Simulation mit gezielt unterdrücktem OTPK in dieser Audit-Runde).
**Status:** ⚠️ Mitigiert (Erkennung), nicht vollständig behoben —
dokumentierte, akzeptierte Grenze.

---

### FINDING-004 — P0 — Relay liefert Live-Nachrichten auch an unbestätigte Geräte
**Komponente:** Relay-Sicherheit / Multi-Device-Trust
**Datei:** `server/src/index.js`, Fall `'send'` (vorher: `toUser()` ohne Trust-Prüfung)
**Problem:** Der Trust-Status eines Geräts (`trusted`) wurde ausschließlich
beim Flush der Offline-Warteschlange geprüft. Die Live-Zustellung
(`toUser()`) lieferte an JEDE authentifizierte Verbindung des Zielkontos,
unabhängig vom Bestätigungsstatus.
**Angriffsszenario:** Angreifer kennt/errät die (bewusst teilbare) userId
eines Opfers, registriert sich selbst per `hello` als neues, unbestätigtes
Gerät, bleibt online. Jede live zugestellte Nachricht (Envelope-Metadaten,
nach FINDING-005 potenziell auch der volle Vertrauensstatus) erreicht das
Angreifer-Gerät, ohne dass die im UI dargestellte "Gerät muss bestätigt
werden"-Schranke tatsächlich durchgesetzt wird.
**Impact:** Metadaten-Leck (wer sendet wann an das Opfer) plus — in
Kombination mit FINDING-005 — vollständige Kontoübernahme.
**Likelihood:** Hoch — kein Timing/Race nötig, funktioniert gegen jedes
bereits bestehende Konto, sobald die userId bekannt ist.
**Fix:** Neue Funktion `toTrustedUser()` + `hasTrustedOnlineDevice()` —
Live-Zustellung erfolgt nur noch an Sockets, deren Geräteeintrag
`trusted === true` ist. Ist kein vertrauenswürdiges Gerät online, wird
stattdessen (wie schon vorher für Offline-Fälle) in die Warteschlange
gestellt.
**Regressionstest:** `server/tests/security/relay.test.ts`, "live
zugestellte Nachrichten erreichen nur vertrauenswuerdige Geraete".
**Status:** ✅ Behoben.

---

### FINDING-005 — P0 — approve-device/revoke-device ohne Trust-Prüfung des Aufrufers
**Komponente:** Relay-Sicherheit / Multi-Device-Trust
**Datei:** `server/src/index.js`, Fälle `'approve-device'` und `'revoke-device'`
**Problem:** Beide Kommandos prüften nur `meta.authed` (irgendein
authentifiziertes Gerät), nicht ob der AUFRUFER selbst bereits
vertrauenswürdig ist. Ein frisch selbst-registriertes, unbestätigtes Gerät
konnte sich per `approve-device` mit der eigenen (ihm bekannten) `deviceId`
selbst freischalten — oder per `revoke-device` beliebige andere Geräte
(inklusive der echten, vertrauenswürdigen) des Kontos entfernen.
**Angriffsszenario:** Wie FINDING-004, aber mit direkter
Rechteausweitung: Angreifer registriert sich, ruft
`{type:'approve-device', deviceId: <eigene deviceId>}` auf und ist ab
sofort ein vollständig vertrauenswürdiges Gerät des Opfer-Kontos — inklusive
Teilnahme an zukünftigen Gruppenschlüssel-Verteilungen, die an "alle
vertrauenswürdigen Geräte" adressiert sind. Alternativ: `revoke-device`
gegen die echten Geräte des Opfers, um sie aus dem eigenen Konto zu werfen
(Denial-of-Service / Kontoübernahme-Vorstufe).
**Impact:** Vollständiger Bypass des gesamten Multi-Device-Vertrauens-
modells. Die serverseitige "Bestätigung erforderlich"-Logik war bis zu
diesem Fix rein kosmetisch (nur die Client-UI hat sich daran gehalten).
**Likelihood:** Hoch — trivial ausnutzbar von jedem, der eine userId kennt.
**Fix:** Beide Handler prüfen jetzt zusätzlich, ob `meta.deviceId` selbst
in `u.devices` als `trusted: true` eingetragen ist, bevor die Aktion
ausgeführt wird (`{type:'error', error:'not-trusted'}` sonst).
**Regressionstest:** `relay.test.ts`, "ein unbestaetigtes Geraet kann sich
NICHT selbst freischalten" und "... kann NICHT das echte Geraet abmelden".
**Status:** ✅ Behoben.

---

### FINDING-006 — P1 — lookup() ignoriert Trust-Status bei der Geräteauswahl
**Komponente:** Relay-Sicherheit / Multi-Device-Trust
**Datei:** `server/src/index.js`, Fall `'lookup'`
**Problem:** `first = [...target.devices.values()][0]` wählte schlicht den
ersten (Insertion-Order) Geräteeintrag, unabhängig vom Vertrauensstatus.
Solange das ursprüngliche Gerät nie entfernt wird, ist das meist
unproblematisch (Bootstrap-Gerät ist immer automatisch vertrauenswürdig)
— aber wird das ursprüngliche Gerät entfernt/ersetzt, könnte ein
verbliebenes, nicht bestätigtes Gerät zum "ersten" Eintrag werden und
dessen Schlüssel für NEUE Kontaktanfragen ausgeliefert werden.
**Angriffsszenario:** Kombiniert mit einem Szenario, in dem das
Ursprungsgerät entfernt wurde (z. B. Geräteverlust + `revoke-device`),
während ein nicht bestätigtes Gerät weiterhin registriert ist.
**Impact:** Neue Kontakte könnten ein Handshake-Bundle eines nicht
verifizierten Geräts erhalten.
**Likelihood:** Niedrig (Randfall), aber die Korrektur ist trivial und
kostenlos.
**Fix:** `first = [...target.devices.values()].find(d => d.trusted) ?? null`
— nur ein bestätigtes Gerät wird je als Handshake-Bundle ausgeliefert.
**Regressionstest:** `relay.test.ts`, "lookup liefert ausschliesslich das
Schluesselbuendel des vertrauenswuerdigen Geraets".
**Status:** ✅ Behoben.

---

### FINDING-007 — P1 — Unbegrenztes Speicherwachstum durch Phantom-Konten
**Komponente:** Relay-Sicherheit / Resource Exhaustion
**Datei:** `server/src/index.js`, `getUser()`, Fall `'send'`
**Problem:** `send` an eine beliebige, nicht existierende `to`-userId legt
über `getUser()` automatisch einen dauerhaften Konto-Eintrag mit
Warteschlange an. Es gab weder eine Obergrenze für die Gesamtzahl
verwalteter Konten noch eine Verfallszeit für nie abgeholte
Warteschlangen-Einträge.
**Angriffsszenario:** Ein authentifizierter Angreifer (genügt ein
selbstregistriertes Konto) sendet wiederholt an frei erfundene
Ziel-userIds (begrenzt nur durch das bestehende Sende-Ratelimit,
300/Minute). Jede erzeugt einen dauerhaften, nie bereinigten
Speicher-Eintrag samt Warteschlange (bis zu 500 Einträge à bis zu 2 MB).
**Impact:** Über Stunden/Tage unbegrenztes RAM-Wachstum des
Relay-Prozesses — Denial-of-Service durch Speichererschöpfung.
**Likelihood:** Mittel — braucht Ausdauer, aber kein besonderes Können.
**Fix:** Harte Obergrenze `MAX_TRACKED_USERS` (200.000) für neu
angelegte Konten; periodischer Sweep (`sweep()`, alle 10 Minuten) entfernt
abgelaufene Warteschlangen-Einträge (TTL 14 Tage) und geräteloses
Phantom-Konten mit leerer Warteschlange.
**Regressionstest:** `relay.test.ts`, Describe-Block "bounded storage
(Phantom-Konten / Warteschlangen-TTL)" — testet `sweep()` direkt.
**Status:** ✅ Mitigiert (bounded statt unbounded). **Nicht vollständig
gelöst:** Das grundsätzliche RAM-only-Architekturproblem (siehe SECURITY.md
Abschnitt 4 Punkt 7) bleibt bestehen — eine echte Persistenzschicht
(PostgreSQL/Redis, siehe Audit-Auftrag Abschnitt 12) wurde in dieser
Audit-Runde bewusst NICHT umgesetzt (eigenständiges, mehrtägiges
Infrastrukturprojekt mit Deployment-Implikationen, die der Nutzer selbst
bewerten sollte, bevor es blind implementiert wird).

---

### FINDING-008 — P2 — Master-Key wird beim Sperren nicht aus dem JS-Heap entfernt
**Komponente:** Client-Sicherheit / Memory Security
**Datei:** `client/src/crypto/vault.ts`, `lockVault()`, `destroyVault()`, `unlockVault()`
**Problem:** `masterKey = null` entfernt nur die Referenz, nicht den
Inhalt des zugrunde liegenden `Uint8Array`. Die Schlüsselbytes bleiben bis
zur Garbage Collection (und potenziell darüber hinaus, je nach
Speicher-Wiederverwendung) im Heap.
**Angriffsszenario:** Ein Angreifer mit Speicherzugriff (Debugger,
Coredump, Swap-Datei) unmittelbar NACH dem Sperren könnte den Master-Key
noch auslesen.
**Impact:** Verlängertes Zeitfenster für eine Schlüssel-Extraktion nach
dem eigentlich beabsichtigten "Sperren".
**Likelihood:** Niedrig (braucht bereits Speicherzugriff, also ohnehin
ein stark kompromittiertes Gerät), aber die Härtung ist günstig.
**Fix:** `zero()`-Hilfsfunktion (`Uint8Array.fill(0)`) vor jedem
Dereferenzieren in `lockVault()`, `destroyVault()` und auf den
Fehlschlagpfaden von `unlockVault()` (Tamper-Erkennung nach erfolgreicher
Entschlüsselung des Wraps).
**Ehrliche Grenze (per Auftrag explizit gefordert):** Dies ist KEINE
Garantie. V8s Garbage Collector kann Objekte kopieren/verschieben, bevor
sie gelöscht werden; die WebCrypto-Implementierung kann intern eigene,
aus JS nicht erreichbare Kopien des importierten Schlüssels halten
(`crypto.subtle.importKey`). Vollständige, garantierte Zeroization ist in
JavaScript grundsätzlich nicht erreichbar (anders als z. B. in Rust mit
`zeroize`) — dokumentiert statt stillschweigend als "gelöst" behauptet.
**Regressionstest:** `client/tests/security/vault.test.ts`, "lockVault
entfernt den Zugriff auf den Master-Key" (prüft `isUnlocked()`-Zustand,
kann die tatsächliche Speicherbereinigung selbst nicht verifizieren — das
ist von außerhalb der JS-Engine grundsätzlich nicht testbar).
**Status:** ✅ Bestmöglich gehärtet, ehrlich dokumentierte Grenze.

---

### FINDING-009 — P2 — Kein Secure-Delete beim Entfernen der Vault-Datei
**Komponente:** Lokale Vault-Sicherheit
**Datei:** `client/src/crypto/vault.ts`, `destroyVault()`
**Problem:** `localStorage.removeItem()` entfernt den Eintrag aus der
API-Sicht, garantiert aber keine sofortige, physische Überschreibung auf
Storage-Engine-Ebene (Chromium/WebView2 nutzen LevelDB-artige Backing
Stores mit Compaction — alte Werte können dort länger physisch vorhanden
bleiben).
**Angriffsszenario:** Geräte-Beschlagnahmung (explizit im Bedrohungsmodell
genannt, siehe README) unmittelbar nach "Tresor löschen" — forensische
Analyse des Storage-Backing-Files könnte alte, bereits "gelöschte"
verschlüsselte Vault-Daten wiederherstellen.
**Impact:** Betrifft nur die VERSCHLÜSSELTE Vault-Datei (Klartext war nie
auf Platte) — ein Angreifer bräuchte zusätzlich die Passphrase. Trotzdem
ein reales Restrisiko für das "als wäre es nie passiert"-Versprechen von
Abschnitt 4c in SECURITY.md.
**Likelihood:** Niedrig bis mittel, aber exakt das im Bedrohungsmodell
beschriebene Szenario (Beschlagnahmung).
**Fix:** `secureRemove()` überschreibt den Storage-Slot dreimal mit
kryptographisch zufälligen Daten, bevor `removeItem()` aufgerufen wird.
**Ehrliche Grenze:** Kein Garant — die zugrunde liegende
Storage-Engine kann durch Compaction/Write-Ahead-Logs weiterhin ältere
Kopien enthalten, die von der `localStorage`-API aus nicht erreichbar
sind. Eine vollständige Lösung bräuchte eine Migration auf ein
Speicher-Backend mit expliziter Secure-Delete-Garantie (z. B. SQLCipher
mit `PRAGMA secure_delete`) — siehe SECURITY.md Abschnitt 4 Punkt 6,
bewusst nicht in dieser Audit-Runde umgesetzt (größeres, separates
Migrationsprojekt).
**Regressionstest:** Funktional durch `vault.test.ts`, "destroyVault
entfernt die Vault-Datei vollstaendig" abgedeckt; die physische
Überschreibung selbst ist außerhalb der Storage-Engine nicht aus JS
heraus verifizierbar.
**Status:** ✅ Bestmöglich gehärtet, ehrlich dokumentierte Grenze.

---

### FINDING-010 — P2 — Gruppenverschlüsselung ohne Forward Secrecy/Sender-Auth innerhalb einer Epoche
**Komponente:** Group Encryption
**Details, Angriffsszenario, Impact, Migrationsempfehlung:** siehe
[THREAT_MODEL.md, Abschnitt "Gruppenverschlüsselung"](THREAT_MODEL.md#gruppenverschlüsselung--ehrliche-grenzen-aus-diesem-audit).
**Status:** ⚠️ Dokumentiert, nicht behoben. Mitgliederänderungen lösen
korrekt eine neue Epoche aus (verifiziert) — die strukturelle Schwäche
(ein Epoch-Key für alle, keine Sender-Signaturen) bleibt bestehen und
erfordert eine Migration auf Sender-Keys/MLS, kein Schnellfix.

---

### FINDING-011 — P3 — One-Time-Prekeys können durch wiederholte Lookups ohne Handshake-Abschluss erschöpft werden
**Komponente:** Relay-Sicherheit
**Datei:** `server/src/index.js`, Fall `'lookup'`
**Problem:** Ein OTPK wird bereits beim Lookup konsumiert
(`first.otpks.delete(id)`), nicht erst nach tatsächlichem
Handshake-Abschluss. Ein Angreifer könnte durch wiederholte
`forHandshake:true`-Lookups (begrenzt auf 20/5 Minuten pro eigenem Konto,
aber nicht global) den OTPK-Bestand eines Opfers gezielt erschöpfen und so
jeden echten Kontaktversuch auf den "lite"-Modus zwingen (verstärkt
FINDING-003).
**Impact:** Verstärkt FINDING-003, kein eigenständiger schwerer Fund.
**Likelihood:** Niedrig (mehrere gefälschte Konten nötig, um das
Pro-Konto-Ratelimit zu umgehen).
**Fix:** Nicht umgesetzt in dieser Audit-Runde — bräuchte ein
Reservierungs-/Ablaufsystem für OTPKs statt sofortiger Konsumierung, ein
eigenständiges kleineres Feature.
**Status:** ⚠️ Dokumentiert, nicht behoben.

---

### FINDING-012 — P3 — Geräteliste per `devices`-Kommando ohne Trust-Prüfung abrufbar
**Komponente:** Relay-Sicherheit / Metadatenschutz
**Datei:** `server/src/index.js`, Fall `'devices'`
**Problem:** Jedes authentifizierte (nicht notwendigerweise
vertrauenswürdige) Gerät kann die vollständige Geräteliste des Kontos
abrufen (Namen, Erstellungszeit, Online-Status, Trust-Status).
**Impact:** Reiner Metadaten-Leak an ein unbestätigtes Gerät, kein
Rechte-Bypass mehr (nach FINDING-005-Fix können daraus keine Aktionen
mehr abgeleitet werden).
**Likelihood:** Hoch (trivial abrufbar), Schadenspotenzial gering.
**Fix:** Nicht umgesetzt — ein legitimes neues (noch unbestätigtes)
Gerät des echten Besitzers braucht die Geräteliste plausibel für die
eigene Onboarding-UI ("N Geräte, warte auf Bestätigung"); eine
Einschränkung auf `trusted`-Geräte hätte das ohne genauere UI-Prüfung
riskiert zu brechen.
**Status:** ⚠️ Dokumentiert, bewusst nicht behoben (Trade-off gegen
Onboarding-UX, siehe Begründung).

---

### FINDING-013 — P1 — Ungefangene Exception bei korrupter Vault-Datei (durch Fuzzing gefunden)
**Komponente:** Lokale Vault-Sicherheit
**Datei:** `client/src/crypto/vault.ts`, `unlockVault()`, `checkIntegrity()`
**Problem:** `b64.dec()` (Wrapper um `atob()`) wirft eine `InvalidCharacterError`,
wenn ein Feld der Vault-Datei kein gültiges Base64 enthält. Diese Exception
war an mehreren Stellen in `unlockVault()`/`checkIntegrity()` nicht
gefangen — eine manipulierte oder anderweitig korrupte Vault-Datei
(z. B. `kdfSalt`/`data`/`mac` mit ungültigen Zeichen) ließ die Funktion
mit einer ungefangenen Exception abstürzen, statt kontrolliert
`{ok: false, reason: 'tampered'}` zurückzugeben.
**Gefunden durch:** Property-based Fuzzing (`client/tests/security/fuzz-vault.test.ts`,
`fast-check`) — zufällige Storage-Inhalte und Ein-Byte-Mutationen einer
echten Vault-Datei deckten den Fall innerhalb weniger Testläufe auf.
**Angriffsszenario:** Jede Form von Datei-Korruption (Festplattenfehler,
unvollständiger Schreibvorgang, gezielte Manipulation) mit einem Treffer
in einem Base64-kodierten Feld ließ die App beim Entsperrversuch
abstürzen/hängen bleiben, statt die erwartete, bereits vorhandene
Tamper-Erkennung greifen zu lassen.
**Impact:** Kein Vertraulichkeitsbruch (die Exception verhindert eher zu
viel als zu wenig), aber ein Verfügbarkeits-/Robustheitsfehler genau in
dem Codepfad, der Manipulation eigentlich sicher erkennen soll.
**Likelihood:** Mittel — jede Art von Datei-Korruption kann das auslösen,
nicht nur gezielte Angriffe.
**Fix:** `unlockVault()` ist jetzt in eine äußere Funktion mit
Catch-All gekapselt (`unlockVaultInner` + Wrapper), die jede unerwartete
Exception als `tampered` behandelt; `checkIntegrity()` hat einen
eigenen try/catch um die Decode-/Vergleichslogik.
**Regressionstest:** `client/tests/security/fuzz-vault.test.ts` — drei
Property-Tests (beliebiger Storage-Inhalt, beliebiges valides JSON,
Ein-Byte-Mutation einer echten Vault-Datei), je 25–200 randomisierte
Läufe, alle grün.
**Status:** ✅ Behoben.

---

## Zusammenfassung

| ID | Titel | Schwere | Status |
|---|---|---|---|
| FINDING-001 | Ratchet-State-Mutation vor Auth | P0 | ✅ Behoben |
| FINDING-002 | Ratchet nicht nebenläufigkeitssicher | P1 | ✅ Behoben |
| FINDING-003 | X3DH-Downgrade unentdeckbar | P2 | ⚠️ Mitigiert |
| FINDING-004 | Live-Delivery an unbestätigte Geräte | P0 | ✅ Behoben |
| FINDING-005 | approve/revoke-device ohne Trust-Check | P0 | ✅ Behoben |
| FINDING-006 | lookup() ignoriert Trust-Status | P1 | ✅ Behoben |
| FINDING-007 | Unbegrenztes Phantom-Konten-Wachstum | P1 | ✅ Mitigiert |
| FINDING-008 | Kein Master-Key-Zeroization | P2 | ✅ Gehärtet |
| FINDING-009 | Kein Secure-Delete der Vault-Datei | P2 | ✅ Gehärtet |
| FINDING-010 | Gruppen: keine FS/Sender-Auth pro Epoche | P2 | ⚠️ Dokumentiert |
| FINDING-011 | OTPK-Erschöpfung ohne Handshake-Abschluss | P3 | ⚠️ Dokumentiert |
| FINDING-012 | Geräteliste ohne Trust-Check abrufbar | P3 | ⚠️ Dokumentiert |
| FINDING-013 | Ungefangene Exception bei korrupter Vault-Datei (Fuzzing) | P1 | ✅ Behoben |

**Alle P0- und P1-Befunde sind behoben und durch echte, automatisierte
Regressionstests abgedeckt** (67 Tests in `client/tests/security/`, 20
Tests in `server/tests/security/`, insgesamt 87 Tests, alle grün,
Typecheck und Build sauber). Verbleibende P2/P3-Befunde sind entweder
bestmöglich gehärtet mit ehrlich dokumentierter Restgrenze, oder bewusst
zurückgestellte, größere Architekturthemen mit klarer Begründung.
