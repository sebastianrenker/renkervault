# METADATA.md — Feldweise Metadaten-Analyse des Envelope-Formats

Vollständige Aufschlüsselung, welches Feld des `Envelope`-Objekts
(`client/src/net/client.ts`) für den Relay-Betreiber sichtbar ist und
welches ausschließlich innerhalb der Ende-zu-Ende-verschlüsselten
Nutzlast (`ct`) liegt. Ergänzt [THREAT_MODEL.md](THREAT_MODEL.md) um die
Feldebene, wie im Audit-Auftrag Abschnitt 5 gefordert.

**Grundprinzip:** Alles außer `ct` selbst (und den für den Handshake
zwingend nötigen Feldern `x3dh`/`header`) ist für den Relay technisch
sichtbares Klartext-JSON — es gibt aktuell KEINE zusätzliche
Envelope-Verschlüsselungsschicht über die reine Payload hinaus.

| Feld | Sichtbar für Relay? | Warum / Anmerkung |
|---|---|---|
| `ct` | ❌ Nein — das ist der eigentliche Ciphertext | AES-256-GCM-verschlüsselt, authentifiziert über den Ratchet- bzw. Gruppen-Schlüssel |
| `chatId` | ✅ Ja | Für Gruppen: zufällige ID, kein Klartext-Gruppenname. Für 1:1: identisch mit der Konto-ID des Gegenübers |
| `chatKind` | ✅ Ja | `direct`/`group` — legt Kommunikationsmuster offen (1:1 vs. Gruppe) |
| `kind` | ✅ Ja | `text`/`file`/`edit`/`delete`/`reaction`/`presence`/`call-*` — der Relay sieht z. B., dass gerade ein Anruf signalisiert wird, auch ohne Audio/Video-Inhalt zu sehen |
| `msgId` | ✅ Ja | Zufällige ID pro Nachricht, kein Klartext-Inhalt, aber ermöglicht Verkettung von edit/delete/reaction-Events zur ursprünglichen Nachricht |
| `ts` | ✅ Ja | Sende-Zeitstempel — direkt nutzbar für Timing-Korrelation (siehe THREAT_MODEL.md, Cover-Traffic-Abschnitt) |
| `fromName` | ✅ Ja | **Bewusster Kompromiss, dokumentiert seit SECURITY.md** — Klartext-Anzeigename des Absenders im Envelope, nicht in `ct`. Ließe sich prinzipiell in die verschlüsselte Payload verschieben, wurde aber aus UI-Einfachheit (Relay muss Push-Vorschauen o. Ä. nicht entschlüsseln können) nicht geändert |
| `fileName` / `fileSize` / `fileMime` | ✅ Ja | Dateiname und -typ sind Klartext; die tatsächliche Byte-Größe ist seit dem Padding-Update (Abschnitt 4g in SECURITY.md) auf eine von 9 Stufen genormt, nicht mehr exakt proportional zur Rohdatei — aber `fileSize` als *Feld* transportiert weiterhin die echte Originalgröße als Metadatum |
| `expiresAt` | ✅ Ja | Ablaufzeit für verschwindende Nachrichten — verrät indirekt die pro Chat konfigurierte Aufbewahrungsdauer |
| `replyTo` (`{id, fromName, preview}`) | ✅ Ja | **Zitat-Vorschautext liegt im Klartext des Envelopes**, nicht in `ct` — der schwächste Punkt der aktuellen Metadaten-Minimierung. Ein Angreifer mit Relay-Sicht sieht damit Textausschnitte, selbst wenn er den Rest der Konversation nicht entschlüsseln kann |
| `forwardedFrom` | ✅ Ja | Name der ursprünglichen Quelle einer weitergeleiteten Nachricht, Klartext |
| `targetMsgId` | ✅ Ja | Referenz-ID bei edit/delete/reaction, keine Inhaltsdaten |
| `emoji` / `reactionOp` | ✅ Ja | Die Reaktion selbst (z. B. 👍) läuft aktuell als Klartext-Feld, nicht durch `ct` |
| `presence` | ✅ Ja | Online/Offline-Signal, Klartext (ohnehin nur Best-Effort, siehe SECURITY.md 3) |
| `header` (`{dh, pn, n}`) | ✅ Ja (zwingend) | Ratchet-Header muss für den Empfänger lesbar sein, um überhaupt entschlüsseln zu können — enthält den öffentlichen DH-Schlüssel und Nachrichtenzähler, keine geheimen Werte |
| `x3dh` (`{ephPub, identityPub, pqCt, otpkId}`) | ✅ Ja (zwingend, nur bei Erstkontakt) | Öffentliche Handshake-Werte, für X3DH konstruktionsbedingt notwendig sichtbar |
| `tag` | ✅ Ja, aber absichtlich NICHT auf die Konto-ID rückführbar | Sealed-Sender-Tag statt Konto-ID ab der zweiten 1:1-Nachricht (siehe SECURITY.md Abschnitt 3a) |
| `from` (Zustell-Metafeld, vom Relay selbst gesetzt) | ✅ Ja bei Erstkontakt, `null` bei Sealed-Sender-Folgenachrichten | Serverseitig aus der authentifizierten WebSocket-Verbindung gesetzt, nicht vom Client übermittelt |

## Priorisierte Empfehlung für weitere Metadaten-Minimierung

Am wertvollsten für eine künftige Härtungsrunde, nach Aufwand/Nutzen
sortiert:

1. **`replyTo.preview` in die verschlüsselte Payload verschieben** —
   größter Klartext-Inhalt-Leak im aktuellen Format, vergleichsweise
   kleiner Umbau (Envelope-Feld → Teil des JSON, das in `ct` landet).
2. **`fromName` in die Payload verschieben** — analog, aber mit dem
   Kompromiss, dass der Relay dann auch bei Erstzustellung an ein neues
   Gerät keinen Anzeigenamen für lokale Push-Vorschauen liefern kann
   (aktuell ohnehin nicht implementiert, also kein realer Funktionsverlust).
3. **`emoji`/`reactionOp` in die Payload verschieben** — geringer
   Nutzen (kurze, generische Werte), aber trivial mit umzusetzen, sobald
   1./2. gemacht sind (gleiches Umbaumuster).
4. **`fileName` verschieben, `fileMime` generisch normieren** (z. B.
   immer `application/octet-stream` im Klartext-Feld, echter Typ nur in
   der Payload) — verhindert Rückschlüsse wie "Anhang ist eine
   `steuererklaerung.pdf`" allein aus Relay-Logs.

Nicht sinnvoll minimierbar ohne fundamentalen Architekturwechsel:
`chatId`, `chatKind`, `ts`, `header`, `x3dh` — diese sind für Routing
bzw. das Protokoll selbst konstruktionsbedingt notwendig sichtbar.
