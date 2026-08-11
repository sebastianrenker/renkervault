# SECURITY_HARDENING_PLAN.md

Stand: 11.08.2026. Dieses Dokument setzt direkt auf zwei bereits
bestehenden, aktuellen Analysen auf, statt sie zu wiederholen:
[SECURITY_AUDIT.md](../SECURITY_AUDIT.md) (14-Angreifer-Threat-Model,
Primitiv-für-Primitiv-Analyse, vollständiger Fund-Katalog) und
[docs/FINDINGS.md](FINDINGS.md) (Funde aus dem vorangegangenen
Hardening-Durchgang). Was hier neu ist: der Umsetzungsstand seit
SECURITY_AUDIT.md (mehrere P1/P2-Funde sind seitdem behoben, siehe
Abschnitt 3) und die neue strategische Frage aus diesem Auftrag —
Human/Agent/Device/Service-Identity und renker-core-Anbindung — die es
im bestehenden Code **nicht gibt** und die hier bewusst nur als
Zielarchitektur dokumentiert, nicht implementiert wird.

## 1. Aktuelle Architektur (Ist-Zustand, verifiziert im Code)

```
client/src/
  crypto/   primitives.ts (X25519/Ed25519/AES-GCM/HKDF/Argon2id-Wrapper,
            alles @noble/* + hash-wasm + WebCrypto, keine Eigenkrypto)
            ratchet.ts (Double Ratchet + X3DH-Hybrid, projekteigene
            Komposition auditierter Primitive)
            pq.ts (ML-KEM-768 via @noble/post-quantum)
            vault.ts (At-Rest: Argon2id→KEK→Master-Key→AES-GCM+HMAC,
            Generation-Counter gegen Rollback, DPAPI-Wrap optional)
            safety.ts, padding.ts
  net/      client.ts (Ed25519-Challenge-Response zum Relay),
            realchat.ts (Sitzungs-/Gruppenschlüssel-Engine)
  ui/       React-Komponenten (Onboarding, Chat, SecurityCenter, ...)
server/src/index.js   Node/ws-Relay, RAM-only mit bounded storage,
                       Ed25519-Auth, Multi-Device-Trust serverseitig
                       durchgesetzt
client/src-tauri/     Tauri-Desktop-Shell, DPAPI-IPC-Commands, jetzt mit
                       expliziter CSP
```

**Identity-Modell (Ist-Zustand):** Es gibt genau EINEN Identitätstyp
(`state/types.ts`: `Identity`) — eine menschliche Kontoidentität mit
eingebetteten Geräte-Feldern (`deviceId`, `deviceName`). Es gibt **keine**
Trennung zwischen Human-, Agent-, Service- oder Session-Identität im
Code — dieses Konzept existiert aktuell nur als Zielbild in diesem
Dokument (siehe Abschnitt 6). Jede `createVault()`-Ausführung erzeugt ein
komplett neues, unabhängiges Schlüsselbündel; es gibt keinen
Client-Flow, um ein zweites Gerät an eine bestehende Identität zu
hängen (SECURITY_AUDIT.md, Abschnitt 0).

## 2. Threat Model (Verweis)

Vollständig in [SECURITY_AUDIT.md](../SECURITY_AUDIT.md) Abschnitt 1
(14 Angreifer) und [docs/THREAT_MODEL.md](THREAT_MODEL.md) (Relay/Tor/
Cover-Traffic/PQ-Schutzgrenzen). Nicht dupliziert hier. Kernaussage
unverändert: Der Relay ist strukturell blind für Klartext (kein
"Zero-Knowledge" im kryptografischen Fachsinn, aber ohne Zugriff auf
Ratchet-/Gruppenschlüssel — Begriff wird in der Doku bewusst vermieden,
siehe Abschnitt 8).

## 3. Bekannte Schwächen — Umsetzungsstand seit SECURITY_AUDIT.md

| Fund | Severity | Stand SECURITY_AUDIT.md | Aktueller Stand |
|---|---|---|---|
| GROUP-A (Epoch-Rollback) | P1 | offen | ✅ behoben (`realchat.ts`, monotone Epoch-Prüfung + Test) |
| VAULT-CSP (Tauri-CSP null) | P1 | offen | ✅ behoben (explizite CSP gesetzt, Build verifiziert) |
| RELAY-ORIGIN | P2 | offen | ✅ behoben (`verifyClient`, opt-in `ALLOWED_ORIGINS`) |
| RELAY-ENUM | P2 | offen | ✅ behoben (dediziertes Lookup-Ratelimit) |
| STORAGE-ROLLBACK | P2 | offen | ✅ behoben (Generation-Counter, Migration für Alt-Format) |
| RATCHET-A (Crash-Persistenz) | P2 | offen | ✅ behoben (sofortiges `saveVault` statt 400ms-Debounce nach jeder Session-Änderung) |
| PASSPHRASE-ROTATE | P2 | offen | ✅ behoben (`changePassphrase()` + UI in SecurityCenter) |
| CI-FEHLT | P2 | offen | ✅ behoben (`.github/workflows/security-ci.yml`: npm audit, typecheck, Tests, Build, `cargo check`, Gitleaks; `.github/dependabot.yml`) |
| RATCHET-B (Snapshot-Sanity) | P3 | offen | ✅ behoben (`fromSnapshot` validiert ns/nr/pn) |
| ARGON2-ERR | P3 | offen | ✅ behoben (`KdfExecutionError`, eigener `UnlockResult`-Grund) |
| **PREKEY-ROTATE** | P2 | offen | ❌ **weiterhin offen** |
| **PREKEY-SIG** | P2 | offen | ❌ **weiterhin offen** |
| **DEVICE-PAIRING** | P2 (Feature-Lücke) | offen | ❌ **weiterhin offen** |
| SAFETY-NUM | P3 | offen | ❌ weiterhin offen (kosmetisch, kein Sicherheitsrisiko) |
| AAD-ENCODING | P3 | offen | ❌ weiterhin offen (Fragilität, kein aktueller Bug) |
| SBOM-FEHLT | P3 | offen | ❌ weiterhin offen |

Für Details/Testabdeckung jedes behobenen Punkts: Commit-Historie dieser
Session bzw. `client/tests/security/`, `server/tests/security/`
(aktuell 54 Client- + 16 Server-Tests, alle grün — siehe Abschnitt 7).

## 4. Security-Critical Components (unverändert gültig, aus SECURITY_AUDIT.md konsolidiert)

1. `crypto/ratchet.ts` — High-Risk (projekteigene Protokollkomposition, kein externes Audit)
2. `crypto/vault.ts` — At-Rest-Schlüsselverwaltung
3. `server/src/index.js` — Autorisierungsentscheidungen (Trust, Rate-Limits)
4. `crypto/pq.ts`, `crypto/primitives.ts` — reine Bibliothekswrapper, kein eigener Krypto-Code
5. `net/realchat.ts` — Gruppenschlüssel-Lebenszyklus

## 5. P0/P1/P2/P3 — konsolidierte Prioritätenliste (Rest-Scope)

**P0:** Keine offenen P0-Funde (beide vorherigen P0-Bugs — Ratchet-State-
Corruption, Relay-Trust-Bypass — sind behoben und regressionsgetestet).

**P1:** Keine offenen P1-Funde mehr (GROUP-A, VAULT-CSP siehe Abschnitt 3).

**P2 (Rest-Scope dieser Planung):**
- PREKEY-SIG: Signed-Prekey ist nicht durch den Identitätsschlüssel signiert (klassisches X3DH-Element fehlt)
- PREKEY-ROTATE: keine automatische Prekey-Rotation
- DEVICE-PAIRING: kein Client-Flow für "Gerät zu bestehender Identität hinzufügen" (Entwurf in SECURITY_AUDIT.md Abschnitt 9)
- Identity-Modell-Trennung (Human/Agent/Device/Service) — siehe Abschnitt 6, NEU in diesem Auftrag

**P3:** SAFETY-NUM, AAD-ENCODING, SBOM-FEHLT (siehe SECURITY_AUDIT.md)

## 6. Identity-/Agent-Architektur — Zielbild (Phase 5 dieses Auftrags, NICHT jetzt implementiert)

**Ist-Zustand:** Ein einziger, undifferenzierter `Identity`-Typ. Kein
Konzept von "Agent" oder "Service" existiert im Code, in der DB, im
Relay-Protokoll oder in der Dokumentation.

**Warum hier nicht direkt implementiert:** Eine saubere Trennung von
Human/Agent/Device/Service/Session-Identität ist eine
Protokoll-Erweiterung, keine lokale Härtung — sie berührt das
Envelope-Format, die Relay-Autorisierungslogik UND das
Vertrauensmodell (ein Agent darf, wie im Auftrag korrekt gefordert,
NICHT automatisch dieselben Rechte wie sein menschlicher Besitzer
erhalten). Das im selben Durchgang wie die übrigen P2-Fixes "nebenbei"
einzuführen würde genau der in diesem Auftrag explizit verbotenen
"große Architektur-Umschreibung ohne vorherige Analyse" entsprechen.

**Vorgeschlagenes Zielmodell** (zur Diskussion, nicht final):

```ts
type PrincipalType = 'human' | 'agent' | 'device' | 'service';

interface Principal {
  type: PrincipalType;
  id: string;                // eigener Identitätsraum pro Typ, nicht global eindeutig über Typen hinweg
  publicKey: string;          // Ed25519 oder X25519, je nach Verwendungszweck
  ownerId?: string;           // fuer 'agent'/'device': welcher 'human' besitzt/autorisiert dies — Pflichtfeld, nie implizit
  capabilities?: string[];    // fuer 'agent'/'service': explizite, nicht vererbte Rechte
  createdAt: number;
  revokedAt?: number;
}
```

Kernprinzip, das in der Implementierung (wenn sie kommt) hart
durchgesetzt werden muss: **`ownerId` und `capabilities` werden nie
implizit von einem `human`-Principal geerbt.** Ein Agent, der im Namen
eines Menschen handelt, braucht eine eigene, im Relay separat
autorisierte und separat widerrufbare Capability-Zusage — genau wie ein
zusätzliches Gerät heute schon (nach den Fixes in Abschnitt 3) eine
eigene, serverseitig geprüfte Trust-Freischaltung braucht, keine
automatisch geerbte.

**Migrationspfad (Skizze, kein Implementierungsplan):**
1. `Identity`-Typ um `principalType: 'human'` erweitern (rückwärtskompatibel, alle bestehenden Konten sind implizit `human`).
2. Relay-`hello` um optionales `principalType` + `ownerId`-Feld erweitern; Server verweigert `agent`/`service`-Anmeldungen ohne gültige, vom `ownerId`-Principal signierte Autorisierungs-Assertion.
3. Envelope-Routing bleibt unverändert (Ciphertext-Routing ist principal-agnostisch) — nur die Autorisierungsebene (wer darf senden/empfangen/Geräte verwalten) wird erweitert.
4. Safety Numbers / Fingerprints müssen den `principalType` mit anzeigen, damit ein Nutzer nicht versehentlich einen Agent für einen Menschen hält.

**renker-core-Anbindung:** `github.com/sebastianrenker/renker-core` war
zum Zeitpunkt dieser Analyse aus dieser Umgebung heraus nicht
einsehbar (kein lokaler Checkout, kein Netzwerkzugriff auf das Repo in
dieser Session). Eine Bewertung von API-Kompatibilität, Datenmodellen
und Versionierung ist ohne Einsicht in den tatsächlichen Code von
renker-core nicht seriös möglich — wird hier bewusst NICHT geraten,
sondern als offener Punkt für eine Folgesitzung mit Zugriff auf beide
Repositories vermerkt. Die Krypto-Grenze (renker-core soll keine
kryptografischen Primitive re-implementieren, sondern falls überhaupt,
nur auf Identity-/Permission-/Audit-Datenmodelle zugreifen) ist als
Leitplanke hier festgehalten, unabhängig vom tatsächlichen renker-core-Code.

## 7. Tests — vorhanden vs. fehlend

**Vorhanden (54 Client- + 16 Server-Tests, Stand nach dieser Session):**
- `client/tests/security/ratchet.test.ts` (20): Grundfluss, Out-of-Order, Packet-Loss, Replay, Tamper, gleichzeitiges Senden, Session-Restore
- `client/tests/security/handshake.test.ts` (8): X3DH-Bindung, Domain-Separation, Low-Order-Point-Rejection, KEM-Reject
- `client/tests/security/vault.test.ts` (18): Duress, Tamper, Rollback-Schutz, Passphrase-Wechsel, Crash-Persistenz
- `client/tests/security/group-security.test.ts` (5): Epoch-Rollback-Schutz
- `client/tests/security/kdf-error.test.ts` (2): Argon2-Fehlerklassifikation
- `server/tests/security/relay.test.ts` (13): Auth-Flow, Lockout, Multi-Device-Trust-Bypass-Regression, bounded Storage, User-Enumeration-Limit
- `server/tests/security/origin.test.ts` (3): Origin-Validierung

**Fehlend (Scope für Phase 4 „Adversarial Testing" dieses Auftrags):**
- Fuzzing/Property-Based Testing für Wire-/Envelope-Parsing (Abschnitt 9 im ursprünglichen Audit-Auftrag dieser Serie) — bisher nur handgeschriebene Malformed-Input-Fälle im Relay-Test, kein systematisches Fuzzing (z. B. fast-check).
- Dedizierte Property-/Invariant-Tests im Stil der 8 in diesem Auftrag genannten Invarianten (z. B. "Revoked device can never create a trusted session") — die zugrunde liegenden Garantien sind einzeln durch bestehende Tests abgedeckt, aber nicht als benannte, wiederverwendbare Invariant-Assertions formuliert.
- Gerätespezifische Szenarien "Cloned Device", "Stolen Session" — aktuell nicht unterscheidbar vom Modell (ein geklontes Gerät mit identischer `deviceId`+`edPub` sieht für den Server wie eine normale Reconnection aus, siehe SECURITY_AUDIT.md Threat #10).
- Identity-/Agent-Tests — nicht anwendbar, solange das Feature nicht existiert (Abschnitt 6).

## 8. Security Maturity Level (pro Bereich, ehrlich, ohne Überschätzung)

| Bereich | Level | Begründung |
|---|---|---|
| Crypto-Primitive | **2 — Hardened** | Ausschließlich auditierte Bibliotheken, korrekt verwendet (siehe Primitiv-Analyse in SECURITY_AUDIT.md) |
| Protokoll-Komposition (Ratchet/X3DH) | **1 — Tested** | Umfangreich intern getestet (28 gezielte Tests), aber **kein externes Audit** — darf nicht als "Hardened" oder höher dargestellt werden |
| Device Trust | **2 — Hardened** | Serverseitig durchgesetzt seit dem letzten Audit, aber kein Pairing-Feature (Level 1 für die UX-Seite) |
| Identity (Human/Agent/Service) | **0 — Prototype** | Existiert nicht im Code — nur als Zielbild in diesem Dokument |
| Server/Relay | **1 — Tested** | Autorisierung korrekt, aber RAM-only, kein Pen-Test |
| Metadata Privacy | **1 — Tested** | Bekannte, dokumentierte Lücken (METADATA.md), keine strukturelle Lösung (Mixnet o. ä.) |
| Client (Web/Tauri) | **1 — Tested** | CSP jetzt gesetzt, aber kein SAST, kein externes Pentest |
| Storage | **2 — Hardened** | Rollback-Schutz, Zeroization-Bestmöglich, Argon2id korrekt parametrisiert |
| CI/CD | **1 — Tested** | Pipeline existiert jetzt (diese Session), aber noch nie in der Praxis gelaufen (kein Push seit Einführung) |

**Kein Bereich erreicht Level 3 oder 4.** Das ist eine korrekte, keine
zu pessimistische Einschätzung — ein internes, wenn auch gründliches
Audit ersetzt kein unabhängiges Review (Level 3) und erst recht keinen
belegten Produktionseinsatz unter echter Last (Level 4).

## 9. Nächste Schritte (Phase 2 dieses Auftrags)

Reihenfolge nach diesem Plan: PREKEY-SIG → DEVICE-PAIRING →
Identity-Modell-Grundgerüst (nur Datenmodell + Dokumentation, keine
volle Agent-Plattform) → Fuzzing/Property-Tests → Doku-Sync.
