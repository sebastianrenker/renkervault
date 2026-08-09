# Split-Custody Deniable Encryption (SCDE)

Ein eigenständiges Verschlüsselungsschema — Konzept-Dokument mit
Sicherheitsargumentation und ehrlicher Einordnung zum Stand der Technik.

Stand: 08.08.2026 · Forschungscharakter, **kein** produktionsreifes,
extern auditiertes Verfahren.

---

## 0. Ehrlicher Vorspann

Bevor der Entwurf beginnt, zwei Klarstellungen, die für dieses Dokument
verbindlich sind:

1. **Es wird keine neue kryptografische Primitive erfunden.** SCDE
   verwendet ausschließlich seit Jahrzehnten öffentlich analysierte
   Bausteine: AES-256-GCM, HKDF-SHA256, Argon2id, Shamir Secret Sharing
   (Shamir, 1979) und einen kryptografisch sicheren Zufallsgenerator. Neu
   ist ausschließlich die **Komposition** dieser Bausteine zu einem neuen
   Protokoll mit einer neuen Eigenschaftskombination.
2. **Ich habe vor dem Entwurf recherchiert, was es zu diesem Thema
   bereits gibt**, um keine falsche Neuheit zu behaupten (Quellen am
   Ende). Ergebnis: "Deniable Secret Sharing" ist ein aktives, noch
   junges Forschungsfeld (u. a. ein IACR-ePrint-Paper von 2025 sowie
   "False-Bottom Encryption: Deniable Encryption From Secret Sharing").
   SCDE ist als **eigenständige Synthese** in diesem Feld zu verstehen,
   nicht als Reproduktion einer bestimmten Arbeit — ich konnte die
   Volltexte der genannten Papers technisch nicht abrufen (IACR blockte
   den automatisierten Zugriff, ResearchGate lieferte einen Serverfehler),
   kann eine 1:1-Überschneidung mit deren genauer Konstruktion also nicht
   ausschließen. Das wird unten unter "Related Work" transparent gemacht.

## 1. Zielsetzung: welche Eigenschaft ist neu?

Bestehende Ansätze lösen jeweils nur eine Teileigenschaft:

| Ansatz | Löst | Löst NICHT |
|---|---|---|
| Passphrasen-Tresor (z. B. RenkerVaults heutiger `vault.ts`) | Vertraulichkeit at-rest | Coercion (eine einzelne Person kann gezwungen werden, die Passphrase zu nennen) |
| Duress-PIN + leere Fake-Ansicht | Verhindert Zugriff auf echte Daten unter Zwang | Eine *leere* Ansicht ist für einen erfahrenen Angreifer selbst verdächtig — "wo sind deine Daten?" |
| VeraCrypt-artige Hidden Volumes | Plausibel befüllte Fake-Daten | Bekanntes Multi-Snapshot-Problem: wiederholte Kopien des Containers über Zeit können verraten, dass sich Bereiche außerhalb der sichtbaren Daten ändern → Indiz für ein verstecktes Volume |
| Shamir Secret Sharing (k-von-n) | Kein Einzelner kann allein entschlüsseln | Für sich genommen keine Deniability — wer Anteile hat, kann unter Zwang trotzdem kooperieren |

**SCDE kombiniert zwei Eigenschaften, die bislang meist getrennt
betrachtet werden, gezielt so, dass sie sich gegenseitig verstärken statt
sich nur zu addieren:**

- **Strukturelle (custodiale) Deniability:** Der Schlüssel für die echten
  Daten liegt *physisch nie vollständig beim Tresor-Besitzer selbst*,
  sondern ist auf *k*-von-*n* getrennte Vertrauensparteien verteilt. Ein
  Angreifer, der den Besitzer zwingt, kann ihn nicht zur Preisgabe eines
  Schlüssels zwingen, den dieser gar nicht besitzt — ein grundlegend
  anderer Deniability-Mechanismus als klassische "hidden volume"-Verfahren,
  die versuchen, den zweiten Schlüssel *auf demselben Gerät* zu verstecken.
- **Plausibel befüllte, kryptografisch ununterscheidbare Zweitschicht:**
  Anders als eine leere Fake-Ansicht enthält der Decoy-Pfad echte,
  plausible (aber unwichtige) Daten — ununterscheidbar vom "echten" Layer,
  solange man keinen der beiden Schlüssel besitzt.

## 2. Bedrohungsmodell

- **Angreifer-Fähigkeiten:** physischer Zugriff auf das Gerät und die
  Containerdatei; kann den Besitzer zur Preisgabe *dessen*, was er weiß,
  zwingen (Passphrase, PIN); kann NICHT gleichzeitig *k* voneinander
  unabhängige Vertrauenspersonen zwingen (Kernannahme, siehe Abschnitt 6).
- **Nicht abgedeckt:** kompromittiertes Endgerät (Keylogger etc.) — wie
  bei jedem Verschlüsselungsverfahren; Kollusion der Vertrauensparteien
  mit dem Angreifer; Multi-Snapshot-Forensik über einen langen Zeitraum
  (siehe Abschnitt 7, ehrliche Grenzen).

## 3. Konstruktion

### 3.1 Setup (einmalig)

```
Eingabe: Decoy-Passphrase P_d, echte Daten M_real, Decoy-Daten M_decoy,
         Schwellenwert (k, n)

1.  salt_d          <- rand(16)
2.  Key_d            = Argon2id(P_d, salt_d)                    // wie vault.ts
3.  secret_real      <- rand(32)                                 // 256-Bit-Geheimnis
4.  shares[1..n]      = ShamirSplit(secret_real, k, n)            // klassisches (k,n)-Schema
5.  Key_r             = HKDF-SHA256(secret_real, "SCDE-real-v1")
6.  L                 = feste Blockgröße (z. B. 1 MiB, für beide Layer identisch)
7.  ct_decoy          = AES-256-GCM(Key_d, pad(M_decoy, L))
8.  ct_real           = AES-256-GCM(Key_r, pad(M_real,  L))
9.  off_d             = HKDF-SHA256(Key_d, "SCDE-offset") mod (Container-Slots)
10. off_r             = HKDF-SHA256(Key_r, "SCDE-offset") mod (Container-Slots)
    // bei Kollision (off_d == off_r): off_r neu würfeln (secret_real neu ziehen), erneut prüfen
11. Container          = rand(Container-Größe)                   // vollständig zufällig vorbelegt
12. Container[off_d]   = ct_decoy
13. Container[off_r]   = ct_real
14. Vertrauensparteien 1..n erhalten je shares[i] getrennt
    (z. B. über die bereits vorhandenen 1:1-Ratchet-Kanäle, wie in
    Kandidat C der vorangegangenen RenkerVault-Analyse beschrieben)
```

Der Container ist danach ein Blob aus Zufallsbytes, in dem an zwei
schlüsselabhängigen, nicht vorhersagbaren Positionen je ein
AES-GCM-Ciphertext liegt — der Rest ist ununterscheidbar davon, da AES-GCM-
Ausgaben computational von echtem Zufall nicht unterscheidbar sind (Standard-
Annahme, dieselbe, auf der auch VeraCrypts Hidden-Volume-Konstruktion
beruht).

### 3.2 Decoy-Pfad (unter Zwang)

```
Eingabe: P_d
1. Key_d = Argon2id(P_d, salt_d)
2. off_d = HKDF-SHA256(Key_d, "SCDE-offset") mod (Container-Slots)
3. M_decoy = AES-256-GCM-Decrypt(Key_d, Container[off_d])
```

Für den Besitzer unter Zwang ist dieser Ablauf identisch zu einer normalen
Passphrasen-Entsperrung — er weiß nichts von `secret_real`, `off_r` oder
den Shares, kann also selbst unter Folter/Nötigung nichts zusätzliches
preisgeben, weil es außerhalb seines Wissens liegt.

### 3.3 Echter Pfad (reguläre Nutzung)

```
Eingabe: k beliebige der n Shares (vom Besitzer bei mindestens k
         Vertrauensparteien angefragt/zusammengeführt — z. B. per
         1:1-Ratchet-Kanal, jeder Trustee schickt seinen Share nur nach
         Rückfrage/Bestätigung, analog zur bestehenden
         Geräte-Bestätigungslogik in RenkerVaults Einbruchsalarm-System)

1. secret_real = ShamirReconstruct(shares_subset)   // benötigt exakt >= k
2. Key_r = HKDF-SHA256(secret_real, "SCDE-real-v1")
3. off_r = HKDF-SHA256(Key_r, "SCDE-offset") mod (Container-Slots)
4. M_real = AES-256-GCM-Decrypt(Key_r, Container[off_r])
```

## 4. Sicherheitsargumentation

**Vertraulichkeit des Decoy-Layers:** reduziert direkt auf die
IND-CPA/IND-CCA-Sicherheit von AES-256-GCM plus die
Preimage-/Brute-Force-Resistenz von Argon2id gegen die Passphrase — exakt
dasselbe Argument, das bereits für RenkerVaults bestehenden Vault gilt.

**Vertraulichkeit des Real-Layers:** reduziert auf zwei unabhängige
Eigenschaften: (a) AES-256-GCM-Sicherheit für `Key_r`, (b) die
informationstheoretische Eigenschaft von Shamirs (k,n)-Schema, dass
*jede* Menge von weniger als *k* Shares **null Information** über
`secret_real` preisgibt (klassisches, bewiesenes Resultat aus Shamir 1979
— kein rechnerisches, sondern ein informationstheoretisches Argument, also
auch gegen einen Angreifer mit unbegrenzter Rechenleistung sicher).

**Deniability (Ununterscheidbarkeit des zweiten Layers):** Ein Angreifer,
der nur `Key_d`/`P_d` kennt (bzw. erzwingt), kann `off_r` nicht berechnen
(er müsste dafür `Key_r` bzw. `secret_real` kennen) und sieht an Position
`off_r` nur Bytes, die er nicht von den übrigen, tatsächlich zufälligen
Container-Bytes unterscheiden kann — unter der Standardannahme, dass
AES-256-GCM-Ausgaben computational ununterscheidbar von Zufallsbytes sind.
Das ist **strukturell dasselbe Argument** wie bei VeraCrypt-Hidden-Volumes,
aber mit einem wichtigen Unterschied: Die Position ist *schlüsselabhängig*
(`off_d`/`off_r` werden aus dem jeweiligen Schlüssel abgeleitet) statt
strukturell fest (z. B. "verstecktes Volume beginnt am Ende des
sichtbaren") — das erschwert naive strukturelle Forensik, die nach einem
bekannten Offset-Muster sucht.

**Coercion-Resistance:** Kein rein kryptografisches, sondern ein
Protokoll-/Bedrohungsmodell-Argument: Da der Tresor-Besitzer `secret_real`
nie besitzt (nur `≥k` getrennte Parteien gemeinsam können es
rekonstruieren), kann *keine* Zwangsmaßnahme gegen ihn allein die echten
Daten offenlegen — die Sicherheit hängt hier explizit von der Annahme ab,
dass nicht gleichzeitig *k* Vertrauensparteien angegriffen werden
(realistisch, wenn sie geografisch/organisatorisch getrennt sind, z. B.
"ein Familienmitglied + ein Anwalt + ein zweites Gerät im Ausland").

## 5. Related Work (ehrlicher Vergleich)

- **VeraCrypt Hidden Volumes:** ältestes praktisches Vorbild für
  ununterscheidbare Zweitschichten in einem Container. Bekannte Schwäche:
  Multi-Snapshot-Angriffe (mehrere Kopien des Containers über Zeit zeigen,
  dass sich "ungenutzter" Bereich ändert) — siehe z. B. *"Toward Robust
  Hidden Volumes Using Write-Only Oblivious RAM"* (ACM CCS 2014) und
  *"RCE-HVE: Plausible Deniability Against Multi-snapshot Adversaries with
  Amplified Storage"* (2025). SCDE erbt dieses Problem strukturell mit
  (siehe Abschnitt 7) — löst es NICHT vollständig, mildert es aber, weil
  bei SCDE keine Software auf dem Gerät selbst jemals beide Layer
  gleichzeitig neu schreibt (der Real-Layer wird nur bei erfolgreicher
  k-von-n-Rekonstruktion aktualisiert, nicht bei jeder normalen Nutzung).
- **"Deniable Secret Sharing"** (IACR ePrint 2025/525) und **"False-Bottom
  Encryption: Deniable Encryption From Secret Sharing"**: beide
  kombinieren, dem Titel/Abstract nach, ebenfalls Secret Sharing mit
  Deniability. Ich konnte die Volltexte nicht laden (siehe Abschnitt 0) —
  SCDE ist daher unabhängig entworfen; ob die konkrete
  Offset-Ableitungs-Konstruktion oder die "Custody liegt nie beim
  Besitzer"-Idee dort in gleicher Form vorkommt, kann ich nicht mit
  Sicherheit ausschließen. Vor jeder echten Nutzung müsste dieser
  Abgleich mit den Originalarbeiten nachgeholt werden.
- **RenkerVaults Duress-PIN (heute):** liefert eine *leere* Fake-Ansicht.
  SCDE ist die konsequente Weiterentwicklung davon (siehe Kandidat C der
  vorherigen Analyse) — plausibel befüllt statt leer, und mit tatsächlicher
  kryptografischer Trennung statt nur einem UI-Modus.

## 6. Kernannahme, die alles trägt

Die gesamte Coercion-Resistance steht und fällt mit einer einzigen,
nicht-kryptografischen Annahme: **die *k* Vertrauensparteien werden nicht
gleichzeitig mit dem Besitzer angegriffen oder kollaborieren nicht mit dem
Angreifer.** Das ist ein Protokoll-Designentscheid (wie bei jedem
Schwellenwert-/Multisig-System), keine mathematische Garantie — muss bei
der Auswahl der Vertrauensparteien (Anzahl, Unabhängigkeit, geografische/
organisatorische Trennung) explizit mitgedacht werden.

## 7. Ehrliche Grenzen

1. **Multi-Snapshot-Forensik ist nicht vollständig gelöst** (siehe
   Abschnitt 5) — ein Angreifer mit mehreren Kopien des Containers über
   Zeit kann durch Differenzanalyse Hinweise auf einen zweiten Layer
   finden, wenn dieser sich verändert, während der Decoy-Layer stabil
   bleibt (oder umgekehrt). Vollständige Lösung bräuchte ein
   Write-Only-ORAM-artiges Schreibmuster — signifikanter Zusatzaufwand,
   hier bewusst nicht mitgelöst.
2. **Container-Größe verdoppelt sich mindestens** (Platz für zwei
   vollwertige, gepaddete Layer plus Zufalls-Overhead).
3. **Kollisionsbehandlung bei `off_d == off_r`** (Schritt 10 in 3.1) ist
   im Konzept nur skizziert — bräuchte eine sauber spezifizierte
   Wiederholungs-/Domain-Separation-Strategie vor jeder Implementierung.
4. **Kein Ersatz für ein externes Kryptografie-Audit.** Wie jede neue
   Protokoll-Komposition (vgl. RenkerVaults eigener Hinweis zu
   `ratchet.ts`) ist SCDE eine Idee, kein geprüftes Verfahren — vor
   echtem Einsatz zwingend: formale Sicherheitsanalyse, unabhängiger
   Kryptografie-Review, Implementierungs-Audit (Seitenkanäle,
   Constant-Time-Vergleiche etc.).
5. **UX-Komplexität:** Schwellenwert-Koordination mit *n* echten Menschen
   ist in der Praxis der schwierigste Teil jedes Threshold-Systems — nicht
   kryptografisch, aber praktisch der wahrscheinlichste Fehlerpunkt.

## 8. Fazit

SCDE ist kein neuer Chiffre-Algorithmus (das wäre unseriös, siehe
Abschnitt 0), sondern eine neue **Protokoll-Komposition** aus geprüften
Bausteinen, die zwei bislang meist getrennt gelöste Eigenschaften —
Custody-basierte Coercion-Resistance und plausibel befüllte Deniability —
gezielt kombiniert. Die Sicherheitsargumentation stützt sich vollständig
auf etablierte Resultate (AES-GCM-IND-CPA, Argon2id, Shamirs
informationstheoretisches Threshold-Resultat); neu ist ausschließlich die
Anordnung. Für einen produktiven Einsatz (z. B. als Erweiterung von
RenkerVaults Duress-Modus) wäre der nächste Schritt eine formale
Ausarbeitung plus externer Review — kein Schritt, den ein Konzept-Dokument
ersetzen kann oder sollte.

---

## Quellen (Recherche für Abschnitt 5)

- [Toward Robust Hidden Volumes Using Write-Only Oblivious RAM (ACM CCS 2014)](https://dl.acm.org/doi/10.1145/2660267.2660313)
- [RCE-HVE: Plausible Deniability Against Multi-snapshot Adversaries with Amplified Storage (Springer, 2025)](https://link.springer.com/chapter/10.1007/978-3-032-01806-9_13)
- [Deniable Secret Sharing (IACR ePrint 2025/525)](https://eprint.iacr.org/2025/525)
- [Deniable Secret Sharing (Springer Nature Link)](https://link.springer.com/chapter/10.1007/978-3-032-12293-3_13)
- [False-Bottom Encryption: Deniable Encryption From Secret Sharing (ResearchGate)](https://www.researchgate.net/publication/371820964_False-Bottom_Encryption_Deniable_Encryption_from_Secret_Sharing)
- [Secret Sharing Deniable Encryption Technique (Springer Nature Link)](https://link.springer.com/chapter/10.1007/978-981-10-4154-9_41)
- Zusätzlich geprüft (Ergebnis: bereits gelöst, daher NICHT als eigener
  Vorschlag übernommen — siehe Begründung unten):
  [Signal: Signal Protocol and Post-Quantum Ratchets (SPQR)](https://signal.org/blog/spqr/) ·
  [Triple Threat: Signal's Ratchet Goes Post-Quantum (Quarkslab)](https://blog.quarkslab.com/triple-threat-signals-ratchet-goes-post-quantum.html) ·
  [Signal's Post-Quantum Cryptographic Implementation (Schneier on Security)](https://www.schneier.com/blog/archives/2025/10/signals-post-quantum-cryptographic-implementation.html)

**Hinweis zur letzten Quellengruppe:** Die ursprünglich naheliegende Idee
für dieses Dokument war ein "kontinuierlicher Post-Quantum-Ratchet"
(periodische ML-KEM-Auffrischung statt nur beim Handshake — genau das,
was in der vorherigen RenkerVault-Analyse als Kandidat A vorgeschlagen
wurde). Die Recherche ergab, dass Signal genau das im Oktober 2025 unter
dem Namen SPQR bereits produktiv ausgerollt hat (chunk-basierte
ML-KEM-Übertragung über mehrere Nachrichten). Deshalb wurde dieser
Ansatz hier **nicht** als "eigenständige neue Erfindung" präsentiert —
das wäre unehrlich gewesen, da es bereits Stand der Technik ist. Für
RenkerVault bliebe es trotzdem ein sinnvoller nächster Schritt, aber dann
als "Übernahme von SPQR-Prinzipien", nicht als eigene Erfindung.
