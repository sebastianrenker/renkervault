# RenkerVault — Vorbereitungsdokument: Audit, Threat-Model-Review, Pen-Test

Für die drei organisatorischen Punkte aus der Härtungs-Roadmap (Stufe 1
Punkt 1, Stufe 2 Punkt 5, Stufe 3 Punkt 10). Zweck: als Scope-Dokument an
externe Prüfer:innen übergeben bzw. als Grundlage für eine Ausschreibung
nutzen — kein Ersatz für die eigentliche Prüfung.

## 1. Externes Kryptografie-Audit

**Empfohlene Reihenfolge:** zuerst dieser Punkt, vor Threat-Model-Review
und Pen-Test (siehe Roadmap-Begründung).

**Scope (Dateien, konkret):**
- `client/src/crypto/ratchet.ts` — Double-Ratchet-Komposition, X3DH-lite-
  Handshake (2-DH/3-DH-Unterscheidung über HKDF-Info-Strings), PQ-Hybrid-
  Integration.
- `client/src/crypto/pq.ts` — ML-KEM-768-Einbindung, Hybrid-Kombination
  mit X25519 per HKDF.
- `client/src/crypto/vault.ts` — At-Rest-Verschlüsselung (Argon2id → KEK
  → Master-Key → AES-256-GCM), HMAC-Manipulationsschutz, Duress-PIN-Logik.
- `client/src/crypto/primitives.ts` — Wrapper-Korrektheit (u. a.
  IV-Generierung pro AES-GCM-Aufruf, Constant-Time-Vergleich in `constEq`).
- `client/src/crypto/safety.ts` — Safety-Number-Berechnung (Kollisions-
  resistenz, deterministische Sortierung beider Public Keys).
- `server/src/index.js` — Ed25519-Challenge-Response-Auth, One-Time-
  Prekey-Verbrauchslogik (`lookup`-Handler).

**Explizit NICHT im Audit-Scope** (bereits auditierte Fremdbibliotheken):
`@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, `hash-wasm`,
WebCrypto selbst.

**Leitfragen für die Prüfer:innen:**
1. Ist die HKDF-Info-String-Trennung zwischen 2-DH-/3-DH- und
   PQ-Hybrid-Varianten tatsächlich kollisionsfrei über alle Codepfade?
2. Verhält sich `skipKeys()` (MAX_SKIP-Begrenzung) korrekt unter
   böswillig konstruierten `pn`/`n`-Headern (DoS/State-Confusion)?
3. Ist die Duress-PIN-Prüfung in `unlockVault()` timing-safe gegenüber
   der regulären Passphrasen-Prüfung (verrät die Antwortzeit, ob eine
   Duress-PIN existiert)?
4. Ist die HMAC-Integritätsprüfung wirklich vor jeder Entschlüsselung
   des Datenblobs garantiert (kein Pfad, der AES-GCM-Entschlüsselung vor
   der MAC-Prüfung ausführt)?

## 2. Formales Threat-Model-Review

**Methodik-Vorschlag:** STRIDE oder LINDDUN (LINDDUN eignet sich hier
besser, da explizit auf Privacy/Linkability ausgelegt — passend zum
Projektziel Überwachungsresistenz) pro Komponente: Client, Relay,
Duress-/Alarm-System, Geräteverwaltung.

**Zu prüfende Annahmen (bewusst als Fragen, nicht als Behauptungen):**
- Hält die Annahme "der Relay-Betreiber ist neugierig, aber nicht aktiv
  bösartig" (honest-but-curious) — oder muss von einem aktiv
  manipulierenden Relay ausgegangen werden (z. B. durch behördliche
  Anordnung gegen den Betreiber)? Das würde weitere Punkte nötig machen
  (z. B. Zertifikats-Pinning UND Client-Signaturen für Server-Antworten).
- Ist die Duress-PIN-Fake-Ansicht gegen einen Angreifer glaubwürdig, der
  bereits weiß, dass RenkerVault einen Duress-Modus hat (Kenntnis der
  README ist öffentlich)?
- Reicht die aktuelle "5 Fehlversuche → Lockout"-Schwelle gegen einen
  Angreifer mit Offline-Zugriff auf die Tresordatei (Brute-Force gegen
  Argon2id direkt, ohne die App-seitige Lockout-Logik zu durchlaufen)?
- Wie verhält sich das Geräteverwaltungs-Modell, wenn ein Angreifer
  physischen Zugriff auf ein bereits `trusted`-Gerät bekommt (nicht nur
  auf die Tresordatei)?

## 3. Pen-Test des Relays

**Empfohlener Zeitpunkt:** nach Abschluss der technischen Stufe-1/2/3-
Maßnahmen aus der Härtungs-Roadmap — ein Test gegen bereits bekannte,
unbehobene Lücken (z. B. fehlendes Cert-Pinning) liefert wenig neue
Erkenntnis.

**Scope:**
- WebSocket-Endpunkt (`server/src/index.js`): Auth-Bypass-Versuche gegen
  die Ed25519-Challenge-Response, Rate-Limit-Umgehung (aktuell 30 msg/s
  pro Socket, 20 Verbindungen pro IP, 15 s Auth-Timeout laut SECURITY.md
  §4 Punkt 12).
- `lookup`-Handler: Race-Conditions beim One-Time-Prekey-Verbrauch
  (kann ein Prekey doppelt ausgegeben werden bei gleichzeitigen
  Anfragen?).
- TLS-Konfiguration (nach Umsetzung von Härtungspunkt 7:
  Zertifikats-Pinning-Umgehung, Downgrade-Versuche auf `ws://`).
- Deploy-Konfiguration (`deploy/Caddyfile`,
  `deploy/renkervault-relay.service`): systemd-Sandbox-Härtung wirklich
  wirksam (Privilege-Escalation-Versuche aus dem Dienst heraus)?

**Explizit außerhalb des Scopes:** Client-seitige Kryptografie (das ist
Aufgabe von Punkt 1, Audit), Social Engineering, physischer Zugriff auf
Nutzergeräte.
