# RenkerVault — Notizen, Sprachnachricht-Ausbau, Anruf, Videoanruf

Architektur-Konzept für vier neue Features. Ziel: jedes Feature muss zum
bestehenden Zero-Knowledge-Prinzip passen ("der Relay-Betreiber hat zu
keinem Zeitpunkt Klartextzugriff") — keines davon darf diesen
Kernanspruch aus README.md unterlaufen.

Reihenfolge (wie gewünscht, aufsteigende Komplexität):
**Notizen → Sprachnachricht-Ausbau → Anruf → Videoanruf.**

---

## 1. Notizen

**Einordnung:** kein neuer Kommunikationskanal, sondern ein neuer
Datentyp im bereits verschlüsselten lokalen Zustand — architektonisch der
mit Abstand einfachste der vier Punkte.

**Datenmodell:** `Note { id, title, body, createdAt, updatedAt, pinned,
tags[] }`, Teil desselben JSON-Zustands, der schon heute über
`vault.ts` → `sealData()`/sealed` läuft (Argon2id → AES-256-GCM + HMAC).
Kein neuer Krypto-Code nötig — Notizen erben automatisch dieselbe
At-Rest-Verschlüsselung, denselben Manipulationsschutz und denselben
Duress-Schutz (im Fake-View unsichtbar) wie der Rest des Vaults.

**Zwei Ausbaustufen, bewusst getrennt:**

1. **Rein lokal** (Standard/MVP): Notizen bleiben geräteweise, kein
   Netzwerkverkehr nötig.
2. **Geräteübergreifende Synchronisation** (optional, später): Notizen
   zwischen den eigenen Geräten abgleichen — technisch dieselbe Mechanik,
   die `net/realchat.ts` schon für echte Kontakt-Sessions nutzt, nur
   zwischen den eigenen Geräteschlüsseln statt zwischen zwei Personen
   (ähnlich Signals "Note to Self"). Bewusst NICHT mit Kontakten teilbar
   — Notizen sind ein persönlicher, kein Kommunikations-Datentyp.

**Sicherheitsrelevanz:** minimal — kein neuer Angriffsvektor, da keine
neue Übertragung. Einzige neue Überlegung: Notizen zählen zum
HMAC-geschützten Gesamtzustand, also erhöht sich die Datenmenge, die bei
jeder Änderung neu versiegelt wird (`saveVault`) — bei sehr langen Notizen
ggf. Performance beachten, kein Sicherheitsproblem.

---

## 2. Sprachnachricht-Ausbau

**Ist-Zustand:** Sprachnachrichten existieren bereits (Mikrofonaufnahme,
verschlüsselter Anhang), begrenzt durch `MAX_FILE_BYTES` (~1,2 MB, siehe
`ui/App.tsx` und `MAX_MSG_BYTES` in `server/src/index.js`) — ausreichend
für kurze Nachrichten, nicht für längere Aufnahmen.

**Ausbau-Vorschläge, nach Aufwand geordnet:**

1. **Waveform-Vorschau & variable Wiedergabegeschwindigkeit** — rein
   clientseitig (Web Audio API), keine Sicherheitsrelevanz, wirkt sich
   nicht auf das Krypto-/Netzwerkmodell aus.
2. **Chunked/gestreamtes Hochladen für längere Aufnahmen** — die feste
   Obergrenze wird durch mehrere verschlüsselte Chunks ersetzt (jeder
   Chunk eigenständig AES-GCM-verschlüsselt, gleiche Envelope-Struktur
   wie heute, nur mit `chunkIndex`/`totalChunks`-Metadatenfeld). Der
   Relay bleibt weiterhin blind — er sieht nur mehr, aber weiterhin
   opake Chunks statt eines. `MAX_MSG_BYTES` je Chunk bleibt bestehen,
   nur die Gesamtlänge wird nicht mehr künstlich gedeckelt.
3. **Optionale, rein lokale Transkription** (Opt-in, standardmäßig AUS):
   Falls gewünscht, ausschließlich mit einem lokal im Browser/Client
   laufenden Modell (z. B. WASM-basiertes Whisper-tiny), NIEMALS über
   einen Cloud-Dienst — sonst würde genau der Client-Side-Scanning-
   Zugriffspunkt entstehen, den RenkerVault laut README bewusst
   vermeidet. Falls keine ausreichend kleine, lokal lauffähige,
   vertrauenswürdige Bibliothek verfügbar ist: Feature auslassen statt
   Kompromiss bei der Serverfreiheit einzugehen.

**Sicherheitsrelevanz:** Punkt 1–2 sind unkritisch (gleiche Garantien wie
heute, nur andere Größenlimits). Punkt 3 ist der einzige, der eine
explizite Leitplanke braucht (lokal oder gar nicht).

---

## 3. Anruf (Sprachanruf, WebRTC, 1:1)

Das ist der erste Punkt, der tatsächlich neue Kryptografie-/
Architekturentscheidungen braucht. Kernfrage: **Wie bleibt ein
Echtzeit-Anruf mit dem Zero-Knowledge-Relay vereinbar, obwohl WebRTC
eigentlich einen Signalisierungsserver UND oft einen Media-Relay (TURN)
braucht?**

### 3.1 Signalisierung über den bestehenden verschlüsselten Kanal

SDP-Angebot/-Antwort und ICE-Kandidaten werden NICHT als neuer,
eigener Klartext-Signalisierungskanal behandelt, sondern als ganz normale
Ratchet-verschlüsselte Envelope-Nachrichten über die bereits bestehende
1:1-Sitzung verschickt (`net/realchat.ts`) — für den Relay identisch zu
jeder anderen Nachricht: er sieht nur einen weiteren opaken Ciphertext,
keine SDP-Daten, keine IP-Adressen im Klartext (auch wenn ICE-Kandidaten
selbst IP-Adressen enthalten — die sind aber Inhalt der Ratchet-
verschlüsselten Nutzlast, nicht Server-Metadatum).

### 3.2 Warum das die eigentliche Medienverschlüsselung trägt

WebRTC verlangt zwingend DTLS-SRTP für jede Verbindung — die Mediendaten
sind also so oder so verschlüsselt. Der bekannte Schwachpunkt ist NICHT
die Verschlüsselung selbst, sondern dass ein böswilliger
Signalisierungsserver die DTLS-Fingerprints in der SDP unbemerkt
austauschen und sich so zwischen die beiden Peers schalten könnte (siehe
["A Study of WebRTC Security"](https://webrtc-security.github.io/) zur
Rolle von DTLS-Fingerprints als Identitätsbindung). Weil die SDP hier
aber durch die bereits Safety-Number-verifizierte Ratchet-Sitzung läuft,
kann der Relay diese Fingerprints nicht unbemerkt manipulieren — ihm
fehlt der Schlüssel. Ergebnis: **echte Ende-zu-Ende-Verschlüsselung der
Anrufmedien, ohne dass eine zusätzliche eigene Medien-Verschlüsselungs-
schicht programmiert werden müsste** — die Sicherheit kommt aus der
Kombination von Standard-WebRTC (DTLS-SRTP) plus bereits vorhandenem,
authentifiziertem Signalisierungskanal.

### 3.3 TURN-Relay (NAT-Traversal)

Wenn eine direkte P2P-Verbindung nicht zustande kommt, braucht WebRTC
einen TURN-Server als reinen Paket-Relay. Wichtig: TURN terminiert KEINE
DTLS-Verbindung, er leitet nur verschlüsselte SRTP-Pakete weiter — sieht
also nie Klartext-Audio, aber sieht IP-Adressen, Paketgröße und Timing
beider Teilnehmer (dasselbe Metadaten-Zugeständnis, das SECURITY.md
Abschnitt 4 Punkt 7 für den Relay ohnehin schon macht). Empfehlung:
eigener, selbst gehosteter TURN-Server (`coturn`), analog zum bereits
selbst gehosteten Relay — kein Vertrauen in einen fremden STUN/TURN-
Anbieter nötig.

### 3.4 Integration mit dem Einbruchsalarm-System

Ein eingehender Anruf von einem noch nicht bestätigten (`untrusted`)
Gerät sollte dieselbe Behandlung bekommen wie eine neue Geräte-Anmeldung
heute schon (SECURITY.md Abschnitt 2): kein automatisches Klingeln,
sondern erst nach manueller Geräte-Bestätigung.

---

## 4. Videoanruf

Baut vollständig auf Abschnitt 3 auf — WebRTC behandelt Audio- und
Video-Spuren im selben `RTCPeerConnection`-Objekt, dieselbe DTLS-SRTP-
Verschlüsselung, dieselbe signalisierungsseitige Absicherung über den
Ratchet-Kanal. Kein grundsätzlich neuer Sicherheitsmechanismus nötig.

**Zusätzlich zu bedenken (rein UX/Privacy, nicht kryptografisch):**

- Kamera-/Mikrofon-Berechtigungen explizit pro Anruf, nicht dauerhaft.
- Standardmäßig kein automatisches Annehmen, kein Autoplay der Kamera.
- Für eine spätere Gruppenanruf-Erweiterung (nicht Teil dieses
  Konzepts) bräuchte es einen SFU (Selective Forwarding Unit) statt
  reinem 1:1-P2P — dann würde Abschnitt 3.2 nicht mehr automatisch
  reichen, weil ein SFU Pakete aktiv weiterverarbeitet. Dafür wäre
  zusätzlich eine Frame-Level-E2E-Verschlüsselung nötig (WebRTC
  "Insertable Streams"/Encoded Transform API, wie sie Google Meet/Zoom
  für E2EE-Gruppenanrufe nutzen) — bewusst außerhalb des Umfangs dieses
  ersten Ausbaus, da 1:1 P2P dafür keinen Bedarf hat.

---

## 5. Reihenfolge & Abhängigkeiten

```
Notizen  ──────────────────────────────► unabhängig, sofort umsetzbar
Sprachnachricht-Ausbau ─────────────────► unabhängig, sofort umsetzbar
Anruf (Audio, WebRTC, Signalisierung
  über bestehenden Ratchet-Kanal) ──────► neue net/-Schicht, keine neue
                                           Krypto-Primitive
Videoanruf ─────────────────────────────► direkt auf Anruf aufbauend,
                                           kein separater Sicherheits-
                                           entwurf nötig
```

## 6. Offene Punkte / Grenzen (ehrlich, wie in SECURITY.md üblich)

1. **Metadaten bei Anrufen:** Relay/TURN sehen weiterhin wer-mit-wem-
   wann telefoniert (Verbindungsaufbau), auch wenn nie Audio/Video im
   Klartext. Gleiche, bereits dokumentierte Grenze wie bei Text-Chats.
2. **Kein Gruppenanruf in diesem Entwurf** — SFU-Architektur und
   Frame-Level-E2E wären ein eigenständiges Folgeprojekt.
3. **Lokale Transkription** nur, wenn eine vertrauenswürdige,
   ausreichend kleine WASM-Bibliothek gefunden wird — sonst auslassen.
4. **DTLS-Fingerprint-Bindung über den Ratchet-Kanal ist eine neue
   Protokoll-Komposition** (wie schon bei `ratchet.ts` selbst) und
   müsste vor Produktivnahme ebenfalls extern geprüft werden — dieselbe
   Einschränkung, die für den Double Ratchet schon gilt.

## Quellen

- [A Study of WebRTC Security](https://webrtc-security.github.io/) — Referenz zu DTLS-Fingerprints als Identitätsbindung und den bekannten Signalisierungs-MITM-Risiken, die Abschnitt 3.2 addressiert.
