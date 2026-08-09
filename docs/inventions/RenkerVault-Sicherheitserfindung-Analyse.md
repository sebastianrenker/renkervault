# RenkerVault — Analyse & Kandidaten für eine neue Sicherheitserfindung

Stand: 08.08.2026 · Basis: Code-Review von `README.md`, `SECURITY.md`,
`client/src/crypto/{primitives,ratchet,pq,vault,safety}.ts`,
`client/src/net/{client,realchat}.ts`, `server/src/index.js`.

## 1. Wo RenkerVault heute steht (Kurzanalyse)

RenkerVault ist für einen Prototyp ungewöhnlich weit: Double Ratchet
(X3DH-lite mit echten One-Time-Prekeys), PQ-Hybrid-Handshake (X25519 +
ML-KEM-768), Argon2id → AES-256-GCM + HMAC am Vault, Zero-Knowledge-Relay,
Duress-PIN mit Fake-Ansicht, Einbruchsalarm (Brute-Force, Geräte-Mismatch,
DB-Integrität), Tor-Hidden-Service-Option, „Sitzung verbrennen". Das deckt
im Wesentlichen den Signal/Threema-Stand der Technik ab plus zwei Extras
(Duress-Modus, PQ-Handshake), die selbst Signal/Threema so nicht anbieten.

Damit die gesuchte „komplett neue Sicherheitserfindung" wirklich neu ist,
darf sie nicht einfach einen der bereits in `SECURITY.md` Abschnitt 4/5
gelisteten offenen Punkte abarbeiten (TLS aktivieren, Audit beauftragen,
PostgreSQL-Store — das ist Fleißarbeit, keine Erfindung). Die folgenden
Kandidaten zielen bewusst auf **Lücken, die im Dokument selbst als
ungelöst benannt sind, aber noch keinen konkreten Lösungsentwurf haben**,
plus zwei Ideen, die über den aktuellen Signal/Threema-Stand hinausgehen.

## 2. Kandidat A (empfohlen): Quantum-Refresh-Ratchet

**Problem (SECURITY.md 4b, wörtlich):** „Nur der Erstkontakt-Handshake
nutzt ML-KEM. Die fortlaufenden Double-Ratchet-Schritte danach basieren
weiterhin auf klassischem X25519-ECDH." Ein Angreifer, der heute
Ciphertext mitschneidet UND in einigen Jahren sowohl den ursprünglichen
Handshake-Zustand als auch spätere Ratchet-Zustände rekonstruieren kann
(z. B. durch einen späteren Gerätekompromiss, der den laufenden Root-Key
offenlegt), kann ab diesem Punkt jede folgende Nachricht klassisch
brechen, sobald X25519 fällt — der PQ-Schutz des Handshakes „verjährt"
faktisch mit der Zeit, in der der Ratchet weiterläuft.

**Mechanismus:** Statt PQ nur einmalig im Handshake zu verwenden, wird
periodisch (z. B. alle *N* DH-Ratchet-Schritte oder alle *T* Tage) ein
zusätzlicher ML-KEM-Anteil in den bestehenden DH-Ratchet-Schritt gemischt
— nicht bei jeder Nachricht (das ist laut `pq.ts` bewusst verworfen worden,
da ML-KEM-Ciphertexte >1 KB pro Schritt zu groß für einen Pro-Nachricht-
Ratchet sind), sondern nur bei den ohnehin schon selteneren DH-Ratchet-
Schritten (`dhRatchet()` in `ratchet.ts`, ausgelöst bei jedem
Kommunikationsrichtungswechsel):

```
KDF_RK(rk, dhOut)                                  // heute
KDF_RK(rk, dhOut || mlkemSharedSecret)              // Vorschlag: "PQ-Refresh"-Variante
```

Der Header (`RatchetHeader`) bekommt ein optionales Feld
`pq?: string` (Base64-ML-KEM-Ciphertext), analog zum bereits vorhandenen
Muster für optionale One-Time-Prekeys (eigener HKDF-Info-String, damit
sich PQ-Refresh- und Normal-Schritte nie kollidieren — exakt das Muster,
das schon in `handshakeInitiator`/`-Responder` für 2-DH vs. 3-DH benutzt
wird). Jede Seite generiert dazu bei ihrem eigenen `dhs`-Schlüsselwechsel
zusätzlich ein frisches ML-KEM-Schlüsselpaar (`newPqKeyPair()` aus `pq.ts`
existiert bereits) und kapselt/entkapselt darüber.

**Was das erreicht:** Der Zeitraum, in dem ein Klartextabschnitt „nur"
durch klassisches X25519 geschützt ist, schrumpft von „für immer nach dem
Erstkontakt" auf „bis zum nächsten PQ-Refresh-Schritt" (z. B. wenige Tage
bei aktiver Konversation). Das ist — soweit im Code/den Docs erkennbar —
über das hinaus, was Signals PQXDH aktuell öffentlich macht (dort bleibt
der volle Ratchet klassisch). Kosten: zusätzlicher Traffic (~1–2 KB pro
Refresh-Schritt) und etwas mehr Rechenzeit, aber nur bei ohnehin seltenen
DH-Ratchet-Ereignissen, nicht pro Nachricht.

**Ehrliche Grenze:** Schützt nur Nachrichten *nach* dem jeweils letzten
PQ-Refresh; ein Angreifer, der genau zwischen zwei Refreshes kompromittiert,
hat weiterhin ein klassisch-only-Fenster. Kein Ersatz für ein externes
Audit — bleibt wie der Rest von `ratchet.ts` eine nicht extern geprüfte
Komposition auditierter Primitive.

## 3. Kandidat B: Unauffälliges Notfall-Signal ("Silent Distress Beacon")

**Problem:** Der bestehende Duress-Modus (`vault.ts`: `unlockVault` prüft
zuerst `file.duress`) ist rein lokal — er öffnet eine leere Fake-Ansicht,
löst aber laut SECURITY.md Abschnitt 2 bewusst **kein** sichtbares
Ereignis aus. Das schützt vor einem Angreifer, der aufs Gerät schaut, hilft
aber niemandem, der tatsächlich in einer Zwangslage ist — es gibt keinen
Weg, unbemerkt Hilfe zu holen.

**Mechanismus:** Wird die Duress-PIN eingegeben, verschickt der Client
*zusätzlich* zur Fake-Ansicht eine ganz normale, für den Relay und einen
mitschauenden Angreifer nicht unterscheidbare verschlüsselte Nachricht an
einen vorher festgelegten Vertrauenskontakt — über den ganz normalen,
längst existierenden 1:1-Ratchet-Kanal (`net/realchat.ts`), gleiche
Größe, gleiches Timing-Muster wie eine normale Textnachricht. Erst beim
Vertrauenskontakt entschlüsselt sie sich zu einem Alarm-Payload statt zu
Chattext. Der Trick: Da der Relay laut Zero-Knowledge-Prinzip ohnehin nur
opaken Ciphertext sieht (Abschnitt 1 in SECURITY.md), ist dieses Signal
für den Server *und* für einen Angreifer, der das Gerät gerade zwingt, die
Duress-PIN einzugeben, ununterscheidbar von „hat gerade eine SMS-artige
Nachricht geschickt".

**Neuheitsgrad:** Bekannte „Panic Button"-Apps signalisieren meist über
einen separaten, erkennbaren Kanal (SMS an Polizei, spezielle App) — das
ist genau das Muster, das ein Angreifer kontrollieren/blockieren kann,
wenn er das Gerät bereits in der Hand hat. Die Erfindung hier ist, den
Alarm **innerhalb des ohnehin unauffälligen, bereits etablierten
E2E-Kanals** zu verstecken, statt einen erkennbar neuen zu öffnen.

**Ehrliche Grenze:** Setzt voraus, dass der Vertrauenskontakt online ist
oder der Relay die Nachricht queued (funktioniert laut Architektur auch
offline). Kein Schutz, wenn der Angreifer den Netzwerkzugriff komplett
kappt, bevor die PIN eingegeben wird.

## 4. Kandidat C: Schwellenwert-Tresor (Shamir-Secret-Sharing-Wiederherstellung)

**Problem:** Aktuell hängt der gesamte Tresor an genau einer Passphrase
(`vault.ts`: `deriveKey(passphrase, kdfSalt)` → wrappt den Master-Key).
Das ist ein Single Point of Failure in zwei Richtungen: Verlust der
Passphrase = Totalverlust; und bei Nötigung („gib die Passphrase raus")
kann eine einzelne Person allein zur Preisgabe gezwungen werden — der
Duress-Modus hilft nur, wenn der Angreifer die Existenz eines echten
Tresors nicht kennt oder nicht misstrauisch wird.

**Mechanismus:** Der Master-Key wird zusätzlich (optional, pro Nutzer
aktivierbar) per Shamir Secret Sharing in *n* Anteile zerlegt, von denen
*k* zur Wiederherstellung nötig sind (z. B. 3-von-5, verteilt auf eigene
Geräte + ausgewählte Vertrauenskontakte, übertragen über deren jeweilige
1:1-Ratchet-Kanäle — dieselbe Verteillogik, die schon für Gruppen-Epoch-
Keys existiert, siehe `newGroupEpochKey()`/Verteilung in `ratchet.ts`).
Damit kann kein einzelner Anteilseigner (auch nicht der Nutzer selbst
unter Zwang) den Tresor allein entschlüsseln — es braucht immer die
Kooperation von *k* getrennten Parteien.

**Neuheitsgrad:** Verschiebt das Bedrohungsmodell von „schütze die eine
Person, die die Passphrase kennt" zu „kein Einzelner kann je gezwungen
werden, allein zu entschlüsseln" — ein Coercion-Resistance-Ansatz, den
Passwort-Tresore i. d. R. nicht anbieten.

**Ehrliche Grenze:** Erhöht die Angriffsfläche (mehr Parteien mit
Schlüsselmaterial) und die UX-Komplexität; muss strikt opt-in bleiben,
sonst widerspricht es dem einfachen „nur ich kenne meine Passphrase"-
Modell, das der Rest der App bewusst verfolgt.

## 5. Kandidat D: Tarn-Traffic gegen Metadaten-Analyse

**Problem:** SECURITY.md Abschnitt 4, Punkt 7, unverändert offen: „Der
Relay sieht wer-mit-wem-wann (Routing). Schutz dagegen (Sealed Sender,
Padding, Cover-Traffic) ist nicht implementiert." Im `server/src/index.js`
gibt es aktuell nur Rate-Limiting, keine Verschleierung von Zeitpunkt/
Größe.

**Mechanismus:** Jeder Client sendet unabhängig vom tatsächlichen
Nachrichtenaufkommen in zufällig gejitterten Intervallen (z. B. Poisson-
verteilt, Mittelwert 30–90 s) fixgroße Dummy-Envelopes an zufällig
gewählte, bereits bekannte Kontakte — ununterscheidbar vom Routing-Format
echter Envelopes, aber vom Empfänger anhand eines Markers in der
verschlüsselten Nutzlast als „ignorieren" erkennbar. Kombiniert mit
Padding echter Nachrichten auf eine feste Blockgröße (z. B. 512 B/2 KB/
16 KB-Stufen) wird die Größen- und Zeitkorrelation, die ein Relay-
Betreiber oder Netzwerk-Beobachter sonst für Kontaktgraph-Analysen nutzen
könnte, deutlich verwässert.

**Neuheitsgrad:** Nicht die Grundidee (Cover Traffic ist bekannt, u. a.
aus Mixnet-Forschung), sondern die konkrete Umsetzung *innerhalb* eines
bereits bestehenden Zero-Knowledge-Relays ohne Architekturwechsel — als
zusätzliche Nachrichtenklasse im bestehenden Envelope-Format, kein neues
Protokoll.

**Ehrliche Grenze:** Kostet dauerhaft Bandbreite/Akku, auch wenn niemand
chattet; bei kleiner Nutzerzahl (wenige Kontakte pro Konto) bleibt die
statistische Verschleierung schwächer als in großen Anonymitätsnetzen.
Löst das Metadaten-Problem nicht vollständig, senkt aber die Kosten eines
naiven Timing-Angriffs deutlich.

## 6. Kandidat E: Hardware-gebundener Tresor-Schlüssel

**Problem:** SECURITY.md 4, Punkt 10: „Kein Schutz gegen kompromittiertes
Endgerät." Aktuell reicht Kenntnis der Passphrase plus Zugriff auf die
`localStorage`-Datei (bzw. später SQLCipher-Datei), um den Tresor überall
zu entschlüsseln — die Datei ist portabel.

**Mechanismus:** Zusätzliche Verschlüsselungsebene, die den Master-Key
nicht nur mit dem Argon2id-KEK wrappt, sondern zusätzlich mit einem
Schlüssel, der in plattformeigener sicherer Hardware liegt und nicht
exportierbar ist (Windows: TPM/DPAPI mit Hardware-Bindung über Tauri-FFI;
Android: Android Keystore mit `setUserAuthenticationRequired`). Ergebnis:
Eine kopierte Tresordatei ist auf einem anderen Gerät selbst mit korrekter
Passphrase nicht entschlüsselbar, weil der zweite Wrap-Layer fehlt.

**Neuheitsgrad:** Verschiebt „gestohlener Laptop + erratene/abgepresste
Passphrase" von „Totalverlust" zu „nutzlos ohne das physische Original-
Gerät" — ein Schritt über reines passphrasenbasiertes At-Rest-Encryption
hinaus, den viele Passwort-Tresore (bewusst wegen Cross-Device-Sync) nicht
gehen, der für RenkerVaults Ein-Geräte-Fokus aber passt.

**Ehrliche Grenze:** Bricht Portabilität (Tresor lässt sich nicht mehr
einfach auf ein neues Gerät kopieren, sondern braucht einen expliziten
Migrations-/Export-Flow); nur auf Desktop/Android mit echter Secure-
Hardware sinnvoll, nicht im Browser-Prototyp.

## 7. Priorisierung

| Kandidat | Neuheitsgrad | Aufwand | Schließt dokumentierte Lücke |
|---|---|---|---|
| A: Quantum-Refresh-Ratchet | hoch | mittel | ja, 4b direkt |
| B: Silent Distress Beacon | hoch | niedrig–mittel | erweitert Abschnitt 2 |
| C: Schwellenwert-Tresor | mittel–hoch | hoch | neu, nicht in SECURITY.md antizipiert |
| D: Tarn-Traffic | mittel | mittel–hoch | ja, Punkt 7 |
| E: Hardware-Bindung | mittel | hoch (pro Plattform) | ja, Punkt 10 |

**Empfehlung:** Mit **A (Quantum-Refresh-Ratchet)** anfangen — es baut
direkt auf vorhandenem Code auf (`pq.ts`, `ratchet.ts` haben bereits alle
nötigen Bausteine), schließt die im eigenen Dokument am klarsten benannte
Lücke, und ist ohne UX-Änderung umsetzbar (läuft unsichtbar im
Hintergrund). **B (Silent Distress Beacon)** als Zweites, da es das
bestehende Kernfeature (Einbruchsalarm/Duress) sinnvoll erweitert und
ebenfalls ohne neue Server-Logik auskommt — beide passen zur Linie „echte
Erfindung, kein bloßes Abhaken der TODO-Liste".

## 8. Nächste Schritte

1. Für Kandidat A: Prototyp des `pq`-Feldes im `RatchetHeader` +
   Trigger-Logik in `dhRatchet()`, isolierter Unit-Test analog zum
   bestehenden Zwei-Browser-Test für den PQ-Handshake.
2. Für Kandidat B: Payload-Format für den versteckten Alarm festlegen
   (fester Marker + Empfängerliste im Vault, analog zu Kontakten).
3. Beide Kandidaten vor Produktivnahme demselben externen Audit
   unterziehen, das SECURITY.md ohnehin schon für `ratchet.ts`/`vault.ts`
   fordert — neue Krypto-Komposition heißt neue Angriffsfläche.
