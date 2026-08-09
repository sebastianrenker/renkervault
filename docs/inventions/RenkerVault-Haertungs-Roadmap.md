# RenkerVault — Härtungs-Roadmap (nach Risiko priorisiert)

Fasst alle offenen Punkte aus SECURITY.md (Abschnitt 4 "Bekannte Grenzen"
und Abschnitt 5 "Vor Produktiveinsatz zwingend") sowie einen zusätzlichen,
dort noch nicht explizit gelisteten Punkt (Hardware-Bindung, siehe
Kandidat E aus der vorherigen Sicherheitserfindungs-Analyse) zusammen,
priorisiert und trennt dabei technische (code-baubare) von
organisatorischen (nicht code-baubaren) Maßnahmen.

**Wichtig vorweg:** "Absolute Sicherheit" ist kein erreichbarer Zustand
— nach Abschluss aller Punkte hier bleiben weiterhin die in SECURITY.md
Abschnitt 4 Punkt 10 benannten, grundsätzlich unlösbaren Grenzen
(kompromittiertes Endgerät, Social Engineering). Ziel dieser Roadmap ist,
alle *lösbaren* Lücken zu schließen, nicht ein unrealistisches
"unhackbar" zu behaupten.

## Priorisierungsmethode

Jeder Punkt wird nach zwei Achsen bewertet: **Schadenspotenzial** (was
konkret bricht, wenn die Lücke ausgenutzt wird — bricht das
Kernversprechen "E2E/Zero-Knowledge" komplett, oder nur eine
Sekundäreigenschaft?) und **Relevanz für das spezifische
Bedrohungsmodell** des Projekts (Überwachungsresistenz laut README-
Hintergrundabschnitt, nicht nur generische App-Sicherheit).

---

## Stufe 1 — Kritisch (untergräbt das Kernversprechen direkt)

### 1. Externes Kryptografie-Audit von `ratchet.ts` / `vault.ts`
**Art:** organisatorisch. **SECURITY.md:** §5.
Alle anderen Maßnahmen setzen voraus, dass diese Protokoll-Komposition
korrekt ist — bisher ist das eine unbewiesene Behauptung, keine geprüfte
Tatsache. Ohne diesen Punkt ist jede weitere Härtung nachrangig, weil sie
auf einem ungeprüften Fundament aufbaut.
*Alternative/Ergänzung (code-baubar, größerer Umbau):* natives libsignal
via Tauri-FFI statt eigener Komposition — im README bereits als möglicher
Ausweg genannt.

### 2. Signierte, reproduzierbare Client-Builds
**Art:** technisch. **SECURITY.md:** §5, §4 Punkt 8.
Ohne signierte Builds kann ein kompromittierter oder genötigter
Server-/Auslieferungsbetreiber (oder ein Angreifer mit Zugriff auf die
Auslieferung) manipulierten Client-Code ausliefern und die komplette
E2E-Verschlüsselung transparent umgehen — strukturell derselbe
Zugriffspunkt, den README im Hintergrund-Abschnitt als das eigentliche
Chat-Kontrolle-Risiko beschreibt (Client-Side-Scanning), nur durch
Kompromittierung statt Regulierung herbeigeführt.

### 3. Dependency-/Supply-Chain-Pinning und -Prüfung
**Art:** technisch. **SECURITY.md:** §5 ("Dependency-Pinning +
Supply-Chain-Prüfung").
Eine kompromittierte transitive Abhängigkeit von `@noble/curves`,
`@noble/hashes`, `@noble/post-quantum` oder `hash-wasm` würde jede andere
Maßnahme in dieser Liste wertlos machen — reale Präzedenzfälle wie
`event-stream` (2018) oder `ua-parser-js` (2021) zeigen, dass genau das
der praktisch häufigste Weg ist, in eine ansonsten solide Kryptografie
einzubrechen.

---

## Stufe 2 — Hoch (untergräbt das spezifische Bedrohungsmodell: Überwachungsresistenz)

### 4. Sealed-Sender-artige Metadaten-Minimierung + Padding/Cover-Traffic
**Art:** technisch. **SECURITY.md:** §4 Punkt 7, §5.
Direkt aus dem README-Hintergrundabschnitt begründet: Ziel ist Resistenz
gegen strukturelle Überwachung, nicht nur Inhalts-Vertraulichkeit. Ohne
diesen Punkt bleibt "wer chattet mit wem, wann, wie oft" auswertbar —
genau die Art Kontaktgraph-Analyse, vor der Chat-Kontrolle-kritische
Nutzer am ehesten geschützt werden wollen, auch ganz ohne
Client-Side-Scanning. (Siehe auch Kandidat D der vorherigen Analyse.)

### 5. Formales Threat-Model-Review
**Art:** organisatorisch. **SECURITY.md:** §5.
Bewusst VOR dem Pen-Test (Punkt 10) einsortiert: ein strukturiertes
Review deckt typischerweise Lücken auf, die weder im Audit (Punkt 1, rein
kryptografisch) noch im Pen-Test (eher technische Exploits) auffallen —
z. B. Annahmen im Duress-/Alarm-Modell, die nur unter realistischer
Bedrohungssimulation sichtbar werden.

### 6. Hardware-gebundener Vault-Schlüssel (Defense-in-Depth)
**Art:** technisch. Nicht explizit in SECURITY.md, sondern Ergänzung zu
§4 Punkt 10 ("kein Schutz gegen kompromittiertes Endgerät") — siehe
Kandidat E der vorherigen Sicherheitserfindungs-Analyse. Besonders
relevant für RenkerVaults reales Einsatzszenario (Beschlagnahmung,
Diebstahl, Duress) — verhindert, dass eine kopierte Tresordatei auf
fremder Hardware nutzbar ist.

---

## Stufe 3 — Mittel (Standard-Hygiene, wichtig aber nicht alleinstellend)

### 7. TLS-Zertifikats-Pinning
**Art:** technisch. **SECURITY.md:** §5.

### 8. SQLCipher + OS-Keychain für die Tauri-Desktop-Variante
**Art:** technisch. **SECURITY.md:** §4 Punkt 5. Wird relevant, sobald
echte Nutzer echte Desktop-Builds statt des Browser-Prototyps verwenden.

### 9. DDoS-Schutz vor dem Relay-Reverse-Proxy
**Art:** technisch + Infrastruktur. **SECURITY.md:** §4 Punkt 12, §5.
Verfügbarkeits-, kein Vertraulichkeitsrisiko.

### 10. Externer Pen-Test des Relays
**Art:** organisatorisch. **SECURITY.md:** §5. Bewusst NACH Stufe 1–3
einsortiert — ein Test gegen bereits bekannte, noch offene Lücken liefert
wenig neue Erkenntnis und verschwendet Testbudget.

---

## Stufe 4 — Niedrig (bereits angemessen, nur Feinschliff)

### 11. Argon2id-Parameter-Kalibrierung
**SECURITY.md:** §4 Punkt 9. Aktuelle Werte (64 MiB, t=4, siehe
`primitives.ts`) liegen laut Code-Kommentar bereits im
OWASP-empfohlenen Rahmen — nur bei Zielhardware-Wechsel neu bewerten.

### 12. Persistenter Server-Store (PostgreSQL)
**SECURITY.md:** §4 Punkt 6. Betriebsrobustheit (Nachrichtenverlust bei
Neustart), kein Confidentiality-Risiko im engeren Sinn.

---

## Zusammenfassung: Reihenfolge

```
Technisch (→ Claude-Code-Bauauftrag):
  3 (Supply-Chain) → 2 (Signierte Builds) → 4 (Metadaten-Minimierung)
  → 6 (Hardware-Bindung) → 7 (Cert-Pinning) → 8 (SQLCipher)
  → 9 (DDoS-Schutz)

Organisatorisch (→ separates Vorbereitungsdokument):
  1 (Krypto-Audit) → 5 (Threat-Model-Review) → 10 (Pen-Test)
```

Die organisatorischen Punkte sind absichtlich VOR den meisten
technischen einsortiert (Stufe 1/2), weil ihr Ergebnis die technische
Priorisierung nachträglich verändern kann — ein Audit-Fund in
`ratchet.ts` wiegt z. B. schwerer als jeder hier gelistete technische
Punkt.
