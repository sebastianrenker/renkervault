/**
 * Double-Ratchet-Sitzungen (nach dem Signal-Protokoll-Prinzip).
 * =============================================================
 * ⚠ TRANSPARENZ-HINWEIS (siehe SECURITY.md):
 * Es existiert derzeit keine gepflegte, auditierte Browser-Bibliothek,
 * die das komplette Signal-Protokoll kapselt (libsignal-protocol-javascript
 * ist archiviert/unmaintained; @signalapp/libsignal-client ist ein natives
 * Node-Modul). Dieser Prototyp komponiert daher den Double-Ratchet-Algorithmus
 * aus AUDITIERTEN Primitiven (@noble X25519/HKDF/HMAC + WebCrypto AES-GCM)
 * streng nach der öffentlichen Signal-Spezifikation
 * (https://signal.org/docs/specifications/doubleratchet/).
 * Die KOMPOSITION selbst ist nicht extern auditiert und müsste vor
 * Produktiveinsatz durch libsignal (nativ, z. B. via Tauri) ersetzt oder
 * extern geprüft werden.
 *
 * Eigenschaften:
 *  - Perfect Forward Secrecy: jede Nachricht hat einen eigenen Message-Key,
 *    der sofort nach Gebrauch verworfen wird.
 *  - Post-Compromise Security: mit jeder Antwort des Gegenübers wird per
 *    DH-Ratchet ein frischer Root-Key etabliert.
 */
import {
  KeyPair, newX25519, dh, hkdfSha256, hmacSha256,
  aesGcmEncrypt, aesGcmDecrypt, b64, utf8, concat, rand,
} from './primitives';
import { pqDecapsulate, pqEncapsulate } from './pq';

const MAX_SKIP = 64; // Obergrenze für zwischengespeicherte Message-Keys

export interface RatchetHeader {
  dh: string;  // aktueller Ratchet-Public-Key des Senders (Base64)
  pn: number;  // Nachrichten in der vorherigen Sendekette
  n: number;   // Index in der aktuellen Sendekette
}

export interface RatchetMessage {
  header: RatchetHeader;
  ct: string;  // Base64: iv || AES-GCM-Ciphertext (AAD = Header)
}

/** KDF_RK aus der Signal-Spez: (rootKey, dhOut) -> (neuer rootKey, chainKey) */
function kdfRk(rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const okm = hkdfSha256(dhOut, rk, 'RenkerVault-DoubleRatchet-RK', 64);
  return [okm.subarray(0, 32), okm.subarray(32, 64)];
}

/** KDF_CK: chainKey -> (nächster chainKey, messageKey) */
function kdfCk(ck: Uint8Array): [Uint8Array, Uint8Array] {
  const next = hmacSha256(ck, new Uint8Array([2]));
  const mk = hmacSha256(ck, new Uint8Array([1]));
  return [next, mk];
}

/** Serialisierbarer Schnappschuss einer Ratchet-Sitzung (für die verschlüsselte
 *  Vault-Persistenz — echte Multi-Client-Chats müssen die Sitzung über
 *  App-Neustarts hinweg fortsetzen können, sonst laufen beide Seiten
 *  auseinander). Enthält ausschließlich Schlüsselmaterial, kein Klartext. */
export interface RatchetSnapshot {
  dhsPriv: string; dhsPub: string;
  dhr: string | null;
  rk: string;
  cks: string | null;
  ckr: string | null;
  ns: number; nr: number; pn: number;
  skipped: [string, string][];
}

export class Ratchet {
  private dhs: KeyPair;                       // eigenes Ratchet-Schlüsselpaar
  private dhr: Uint8Array | null = null;      // Ratchet-Public-Key der Gegenseite
  private rk: Uint8Array;                     // Root-Key
  private cks: Uint8Array | null = null;      // Sendekette
  private ckr: Uint8Array | null = null;      // Empfangskette
  private ns = 0; private nr = 0; private pn = 0;
  private skipped = new Map<string, Uint8Array>(); // übersprungene Message-Keys

  private constructor(rk: Uint8Array, dhs: KeyPair) {
    this.rk = rk;
    this.dhs = dhs;
  }

  toSnapshot(): RatchetSnapshot {
    return {
      dhsPriv: b64.enc(this.dhs.priv), dhsPub: b64.enc(this.dhs.pub),
      dhr: this.dhr ? b64.enc(this.dhr) : null,
      rk: b64.enc(this.rk),
      cks: this.cks ? b64.enc(this.cks) : null,
      ckr: this.ckr ? b64.enc(this.ckr) : null,
      ns: this.ns, nr: this.nr, pn: this.pn,
      skipped: [...this.skipped].map(([k, v]) => [k, b64.enc(v)]),
    };
  }

  static fromSnapshot(s: RatchetSnapshot): Ratchet {
    const r = new Ratchet(b64.dec(s.rk), { priv: b64.dec(s.dhsPriv), pub: b64.dec(s.dhsPub) });
    r.dhr = s.dhr ? b64.dec(s.dhr) : null;
    r.cks = s.cks ? b64.dec(s.cks) : null;
    r.ckr = s.ckr ? b64.dec(s.ckr) : null;
    r.ns = s.ns; r.nr = s.nr; r.pn = s.pn;
    r.skipped = new Map(s.skipped.map(([k, v]) => [k, b64.dec(v)]));
    return r;
  }

  /** Initiator (Alice): kennt den Ratchet-Public-Key der Gegenseite. */
  static initAlice(sharedSecret: Uint8Array, theirRatchetPub: Uint8Array): Ratchet {
    const r = new Ratchet(sharedSecret, newX25519());
    r.dhr = theirRatchetPub;
    [r.rk, r.cks] = kdfRk(r.rk, dh(r.dhs.priv, r.dhr));
    return r;
  }

  /** Responder (Bob): stellt sein Ratchet-Schlüsselpaar bereit. */
  static initBob(sharedSecret: Uint8Array, ownRatchet: KeyPair): Ratchet {
    return new Ratchet(sharedSecret, ownRatchet);
  }

  /** Nachricht verschlüsseln; der Message-Key wird danach verworfen (PFS). */
  async encrypt(plaintext: Uint8Array): Promise<RatchetMessage> {
    if (!this.cks) throw new Error('Sendekette nicht initialisiert');
    const [next, mk] = kdfCk(this.cks);
    this.cks = next;
    const header: RatchetHeader = { dh: b64.enc(this.dhs.pub), pn: this.pn, n: this.ns };
    this.ns += 1;
    const aad = utf8.enc(JSON.stringify(header));
    const ct = await aesGcmEncrypt(mk, plaintext, aad);
    return { header, ct: b64.enc(ct) };
  }

  /** Nachricht entschlüsseln (inkl. DH-Ratchet-Schritt und Skipped-Keys). */
  async decrypt(msg: RatchetMessage): Promise<Uint8Array> {
    const aad = utf8.enc(JSON.stringify(msg.header));
    const data = b64.dec(msg.ct);

    // 1) Wurde der Key bereits übersprungen (Out-of-Order-Zustellung)?
    const skipKey = `${msg.header.dh}:${msg.header.n}`;
    const skippedMk = this.skipped.get(skipKey);
    if (skippedMk) {
      this.skipped.delete(skipKey);
      return aesGcmDecrypt(skippedMk, data, aad);
    }

    // 2) Neuer Ratchet-Public-Key der Gegenseite -> DH-Ratchet-Schritt
    const theirDh = b64.dec(msg.header.dh);
    if (!this.dhr || b64.enc(this.dhr) !== msg.header.dh) {
      this.skipKeys(msg.header.pn);          // Restkeys der alten Kette sichern
      this.dhRatchet(theirDh);
    }

    // 3) Bis zur Nachricht n vorspulen, Zwischenkeys aufheben
    this.skipKeys(msg.header.n);
    if (!this.ckr) throw new Error('Empfangskette nicht initialisiert');
    const [next, mk] = kdfCk(this.ckr);
    this.ckr = next;
    this.nr += 1;
    return aesGcmDecrypt(mk, data, aad);
  }

  /** Öffentlicher Ratchet-Key (für Fingerprint-Anzeige). */
  get publicKey(): Uint8Array { return this.dhs.pub; }

  private skipKeys(until: number): void {
    if (!this.ckr) return;
    if (this.nr + MAX_SKIP < until) throw new Error('Zu viele übersprungene Nachrichten');
    while (this.nr < until) {
      const [next, mk] = kdfCk(this.ckr);
      this.ckr = next;
      this.skipped.set(`${b64.enc(this.dhr!)}:${this.nr}`, mk);
      this.nr += 1;
      if (this.skipped.size > MAX_SKIP) {
        // ältesten Eintrag verwerfen (bounded memory)
        const first = this.skipped.keys().next().value as string;
        this.skipped.delete(first);
      }
    }
  }

  private dhRatchet(theirDh: Uint8Array): void {
    this.pn = this.ns;
    this.ns = 0;
    this.nr = 0;
    this.dhr = theirDh;
    [this.rk, this.ckr] = kdfRk(this.rk, dh(this.dhs.priv, this.dhr));
    this.dhs = newX25519();
    [this.rk, this.cks] = kdfRk(this.rk, dh(this.dhs.priv, this.dhr));
  }
}

// ---------------------------------------------------------------------------
// Initialer Schlüsselaustausch ("X3DH-lite", 2-DH + veröffentlichter Prekey,
// hybrid um ML-KEM-768 ergänzt — siehe crypto/pq.ts)
// ---------------------------------------------------------------------------
/**
 * Initialer Handshake mit zwei bis drei DH-Berechnungen PLUS einem
 * post-quantensicheren KEM-Anteil (hybrid):
 *   SK = HKDF( DH(IK_a, IK_b) || DH(EK_a, SPK_b) [|| DH(EK_a, OPK_b)] || ML-KEM-SharedSecret )
 * SPK_b ist ein von Bob im Voraus veröffentlichter, wiederverwendbarer
 * X25519-"Signed Prekey" (hier ohne Signatur — Authentizität kommt aus dem
 * Ed25519-Challenge-Response-Login beim Relay, siehe net/client.ts).
 * SPK_b dient zugleich als Bobs initialer Double-Ratchet-Schlüssel, damit
 * Alice sofort verschlüsseln kann, ohne dass Bob online sein muss
 * (asynchroner Erstkontakt).
 *
 * OPK_b ist, sofern beim Lookup verfügbar, ein zusätzlicher, garantiert nur
 * EINMAL verwendeter Prekey (siehe net/realchat.ts: addOneTimePrekeys/
 * consumeOneTimePrekey). Der Relay gibt jeden One-Time-Prekey nur an EINEN
 * Lookup-Anfragenden heraus und entfernt ihn danach aus seinem Bestand
 * (server/src/index.js: 'lookup'-Handler) — das ist der entscheidende
 * Unterschied zum wiederverwendbaren Signed Prekey: Selbst wenn SPK_b
 * jemals kompromittiert würde, bliebe ein mit OPK_b geschützter Handshake
 * sicher, da der private OPK-Schlüssel nach einmaliger Benutzung sofort
 * verworfen wird (Perfect Forward Secrecy bereits für den Erstkontakt
 * selbst, nicht erst ab der zweiten Nachricht wie beim reinen 2-DH-Fall).
 * Ist kein One-Time-Prekey mehr verfügbar (Pool leer/noch nicht befüllt),
 * fällt der Handshake automatisch auf die 2-DH-Variante zurück — dieser
 * Fall wird über einen eigenen HKDF-Info-String von der 3-DH-Variante
 * unterschieden, damit beide Ableitungen niemals denselben Schlüssel
 * erzeugen können, selbst bei sonst identischen Eingaben.
 *
 * Der ML-KEM-Anteil schützt SK gegen "Harvest Now, Decrypt Later" durch
 * einen künftigen Quantencomputer — siehe crypto/pq.ts für die genaue
 * Einordnung (nur der Handshake ist so geschützt, nicht der fortlaufende
 * Ratchet). Da SK per HKDF aus ALLEN Anteilen kombiniert wird, bleibt die
 * Sicherheit mindestens auf dem bisherigen X25519-Niveau, selbst falls
 * ML-KEM sich als fehlerhaft herausstellen sollte.
 */
export function handshakeInitiator(
  myIdentity: KeyPair, theirIdentityPub: Uint8Array, theirPrekeyPub: Uint8Array,
  theirPqPrekeyPub: Uint8Array, theirOneTimePrekeyPub?: Uint8Array
): { sk: Uint8Array; ephPub: Uint8Array; pqCipherText: Uint8Array } {
  const eph = newX25519();
  const { cipherText: pqCipherText, sharedSecret: pqSecret } = pqEncapsulate(theirPqPrekeyPub);
  const parts = [dh(myIdentity.priv, theirIdentityPub), dh(eph.priv, theirPrekeyPub)];
  if (theirOneTimePrekeyPub) parts.push(dh(eph.priv, theirOneTimePrekeyPub));
  parts.push(pqSecret);
  const sk = hkdfSha256(
    concat(...parts), new Uint8Array(32),
    theirOneTimePrekeyPub ? 'RenkerVault-X3DH-full-PQ-hybrid' : 'RenkerVault-X3DH-lite-PQ-hybrid', 32
  );
  return { sk, ephPub: eph.pub, pqCipherText };
}

export function handshakeResponder(
  myIdentity: KeyPair, myPrekey: KeyPair, theirIdentityPub: Uint8Array, theirEphPub: Uint8Array,
  myPqPrekeySecret: Uint8Array, pqCipherText: Uint8Array, myOneTimePrekey?: KeyPair
): Uint8Array {
  const pqSecret = pqDecapsulate(pqCipherText, myPqPrekeySecret);
  const parts = [dh(myIdentity.priv, theirIdentityPub), dh(myPrekey.priv, theirEphPub)];
  if (myOneTimePrekey) parts.push(dh(myOneTimePrekey.priv, theirEphPub));
  parts.push(pqSecret);
  return hkdfSha256(
    concat(...parts), new Uint8Array(32),
    myOneTimePrekey ? 'RenkerVault-X3DH-full-PQ-hybrid' : 'RenkerVault-X3DH-lite-PQ-hybrid', 32
  );
}

/**
 * Gruppen-Verschlüsselung ("Sender-Keys-lite"):
 * Pro Gruppen-Epoche ein zufälliger Gruppenschlüssel. Bei jeder
 * Mitgliederänderung wird eine NEUE Epoche erzeugt (Rekeying), damit
 * entfernte Mitglieder keine späteren Nachrichten lesen können.
 * (Die Verteilung des Epoch-Keys an Mitglieder läuft über deren 1:1-
 * Ratchet-Kanäle; im Demo-Modus simuliert.)
 */
export function newGroupEpochKey(): Uint8Array { return rand(32); }
