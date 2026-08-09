/**
 * Echte 1:1- und Gruppen-Verschlüsselungs-Engine für WIRKLICHE Gesprächs-
 * partner über den Relay-Server (Gegenstück zu demo/seed.ts, das simulierte
 * In-Process-Peers real verschlüsselt).
 * ============================================================================
 * Verwaltet die im RAM lebenden Double-Ratchet-Sitzungen und Gruppen-Epoch-
 * Keys. Sitzungs-Snapshots werden über den verschlüsselten Vault persistiert
 * (crypto/vault.ts), damit echte Sitzungen einen App-Neustart überleben —
 * andernfalls würden zwei echte Nutzer nach einem Neustart auseinanderlaufen
 * (im Gegensatz zum Demo-Modus, der bewusst pro Start neu aushandelt).
 */
import {
  KeyPair, aesGcmDecrypt, aesGcmEncrypt, b64, hex, hkdfSha256, newX25519, rand, sha256Bytes, utf8,
} from '../crypto/primitives';
import { padToTier, unpadFromTier } from '../crypto/padding';
import {
  Ratchet, handshakeInitiator, handshakeResponder, newGroupEpochKey,
} from '../crypto/ratchet';
import { groupFingerprint } from '../crypto/safety';
import { Contact, Identity, StoredSession } from '../state/types';
import { Envelope } from './client';

const OTPK_LOW_WATERMARK = 15; // unter dieser Anzahl wird lokal aufgefuellt
const OTPK_TARGET = 25;        // Zielgroesse des Pools nach dem Auffuellen
const OTPK_MAX_STORE = 60;     // Obergrenze, um den Vault nicht unbegrenzt wachsen zu lassen

/**
 * "Sealed Sender" fuer bereits bestehende 1:1-Sitzungen (SECURITY.md Punkt 7):
 * Aus dem gemeinsamen Sitzungsgeheimnis wird ein kurzes, fuer Aussenstehende
 * NICHT auf die Konto-ID zurueckfuehrbares Tag abgeleitet. Beide Seiten
 * berechnen dasselbe Tag unabhaengig voneinander (kein zusaetzlicher
 * Roundtrip). Der Relay leitet Folgenachrichten nur noch anhand dieses Tags
 * weiter und schreibt die Konto-ID des Absenders NICHT mehr in die
 * zugestellte/zwischengespeicherte Nachricht (server/src/index.js, Fall
 * 'send'). Der Relay-BETREIBER kennt den Absender weiterhin aus der
 * authentifizierten Verbindung selbst (unvermeidbar ohne anonyme
 * Zugangs-Credentials, siehe SECURITY.md) — dieses Tag reduziert also, WAS
 * bei einem Datenabzug/Log-Leck als Klartext-Metadaten sichtbar waere, nicht
 * die Sichtbarkeit fuer den live mitlesenden Betreiber selbst.
 * NUR fuer Folgenachrichten innerhalb einer bestehenden Sitzung moeglich:
 * beim allerersten Kontakt (X3DH-Envelope) kennt die Gegenseite noch kein
 * Tag, das sie einer Person zuordnen koennte — dort bleibt die Konto-ID
 * weiterhin server-sichtbar (siehe encryptDirect/acceptFirstMessage unten).
 */
function deriveSessionTag(sk: Uint8Array): string {
  return hex(hkdfSha256(sk, new Uint8Array(32), 'RenkerVault-SealedSender-Tag', 16));
}

/**
 * Cover-Traffic-Marker (Härtungs-Roadmap Punkt 4 / Kandidat D der
 * Sicherheitserfindungs-Analyse): ein fester, öffentlich bekannter
 * 32-Byte-Wert, der als KOMPLETTER Klartext einer Dummy-Nachricht dient.
 * Entscheidend: Diese Nachrichten laufen als ganz normale `kind: 'text'`-
 * Envelopes über beginSession/encryptDirect — für den Relay identisch zu
 * einer echten Nachricht (gleiches Feld-Layout, gleiche nach padToTier()
 * gerundete Chiffretext-Größe). Der Marker steckt AUSSCHLIESSLICH in der
 * Ende-zu-Ende-verschlüsselten Nutzlast, die nur der jeweilige Empfänger
 * lesen kann (net/../ui/App.tsx: handleDeliver verwirft die Nachricht dort
 * still, ohne UI-Eintrag/Unread-Bump). Würde stattdessen ein eigenes
 * Envelope-`kind` (z. B. "cover") verwendet, könnte der Relay Cover-Traffic
 * trivial an diesem Klartextfeld herausfiltern — genau das, was dieser
 * Mechanismus verhindern soll.
 * Kollisionsrisiko mit echten Nachrichten: astronomisch gering (ein Nutzer
 * müsste exakt diese 32 Rohbytes — keinen gültigen Text, sondern einen
 * SHA-256-Hash — als gesamten Nachrichteninhalt eingeben).
 */
const COVER_TRAFFIC_MARKER = sha256Bytes(utf8.enc('RenkerVault-CoverTraffic-v1'));

function isCoverTrafficMarker(plaintext: Uint8Array): boolean {
  if (plaintext.length !== COVER_TRAFFIC_MARKER.length) return false;
  let diff = 0;
  for (let i = 0; i < plaintext.length; i++) diff |= plaintext[i] ^ COVER_TRAFFIC_MARKER[i];
  return diff === 0;
}

class RealChatEngine {
  private ratchets = new Map<string, Ratchet>();                       // peerUserId -> Sitzung
  // peerUserId -> unser Ephemeral-Pub + ML-KEM-Ciphertext + ggf. verwendeter
  // One-Time-Prekey der Gegenseite (bis 1. Nachricht raus ist)
  private pendingHandshake = new Map<string, { ephPub: string; pqCt: string; otpkId?: string }>();
  private groupKeys = new Map<string, { key: Uint8Array; epoch: number }>(); // chatId -> Epoch-Key
  // eigene, noch unverbrauchte One-Time-Prekeys (volles X3DH) — id -> Schluesselpaar
  private oneTimePrekeys = new Map<string, KeyPair>();
  private sessionTags = new Map<string, string>();  // peerUserId -> unser Sealed-Sender-Tag
  private tagToPeer = new Map<string, string>();     // Tag -> peerUserId (Ruecklookup beim Empfang)

  /** Beim Entsperren: Sitzungen/Gruppenschlüssel/One-Time-Prekeys aus dem Vault laden. */
  hydrate(
    sessions: Record<string, StoredSession>,
    groupKeys: Record<string, { key: string; epoch: number }>,
    oneTimePrekeys: Record<string, { priv: string; pub: string }> = {}
  ): void {
    this.ratchets.clear(); this.pendingHandshake.clear(); this.groupKeys.clear(); this.oneTimePrekeys.clear();
    this.sessionTags.clear(); this.tagToPeer.clear();
    for (const [peerId, s] of Object.entries(sessions)) {
      this.ratchets.set(peerId, Ratchet.fromSnapshot(s.ratchet));
      if (s.tag) {
        this.sessionTags.set(peerId, s.tag);
        this.tagToPeer.set(s.tag, peerId);
      }
      if (s.initiator && !s.handshakeSent) {
        // Kante: Kontakt angelegt, aber App beendet, bevor die erste
        // Nachricht raus ist. Ohne den ursprünglichen Ephemeral-Key können
        // wir keinen neuen Handshake ausgeben (Bob kennt nur den alten) —
        // in diesem seltenen Fall wird der Kontakt beim nächsten Senden
        // automatisch neu gehandshaked (siehe App.tsx: hasPendingHandshake).
      }
    }
    for (const [chatId, g] of Object.entries(groupKeys)) {
      this.groupKeys.set(chatId, { key: b64.dec(g.key), epoch: g.epoch });
    }
    for (const [id, kp] of Object.entries(oneTimePrekeys)) {
      this.oneTimePrekeys.set(id, { priv: b64.dec(kp.priv), pub: b64.dec(kp.pub) });
    }
  }

  /** Aktuellen Zustand aller Sitzungen für die Vault-Persistenz exportieren. */
  snapshotSessions(prevInitiator: Record<string, boolean>): Record<string, StoredSession> {
    const out: Record<string, StoredSession> = {};
    for (const [peerId, ratchet] of this.ratchets) {
      out[peerId] = {
        peerUserId: peerId,
        ratchet: ratchet.toSnapshot(),
        initiator: prevInitiator[peerId] ?? true,
        handshakeSent: !this.pendingHandshake.has(peerId),
        tag: this.sessionTags.get(peerId) ?? '',
      };
    }
    return out;
  }

  /** Konto-ID zu einem Sealed-Sender-Tag auflösen (Empfangsseite, nur für
   *  bereits bestehende Sitzungen — siehe deriveSessionTag oben). */
  resolvePeerByTag(tag: string): string | undefined {
    return this.tagToPeer.get(tag);
  }

  snapshotGroupKeys(): Record<string, { key: string; epoch: number }> {
    const out: Record<string, { key: string; epoch: number }> = {};
    for (const [chatId, g] of this.groupKeys) out[chatId] = { key: b64.enc(g.key), epoch: g.epoch };
    return out;
  }

  /** Aktueller One-Time-Prekey-Bestand für die Vault-Persistenz (volles X3DH). */
  snapshotOneTimePrekeys(): Record<string, { priv: string; pub: string }> {
    const out: Record<string, { priv: string; pub: string }> = {};
    for (const [id, kp] of this.oneTimePrekeys) out[id] = { priv: b64.enc(kp.priv), pub: b64.enc(kp.pub) };
    return out;
  }

  hasSession(peerId: string): boolean { return this.ratchets.has(peerId); }

  oneTimePrekeyCount(): number { return this.oneTimePrekeys.size; }

  /** Falls der lokale Bestand unter die Wasserlinie faellt, neue Einmal-
   *  Prekeys erzeugen (bis OTPK_TARGET, gedeckelt durch OTPK_MAX_STORE).
   *  Gibt die NEU erzeugten oeffentlichen Haelften zum Veroeffentlichen
   *  zurueck (leer, wenn bereits genug vorhanden sind). */
  topUpOneTimePrekeys(): { id: string; pub: string }[] {
    if (this.oneTimePrekeys.size >= OTPK_LOW_WATERMARK) return [];
    const toCreate = Math.min(OTPK_TARGET - this.oneTimePrekeys.size, OTPK_MAX_STORE - this.oneTimePrekeys.size);
    const created: { id: string; pub: string }[] = [];
    for (let i = 0; i < toCreate; i++) {
      const kp = newX25519();
      const id = hex(rand(8));
      this.oneTimePrekeys.set(id, kp);
      created.push({ id, pub: b64.enc(kp.pub) });
    }
    return created;
  }

  /** Alle noch unverbrauchten eigenen One-Time-Prekeys — z. B. um sie nach
   *  einem Reconnect erneut (idempotent) beim Relay zu hinterlegen. */
  publishableOneTimePrekeys(): { id: string; pub: string }[] {
    return [...this.oneTimePrekeys].map(([id, kp]) => ({ id, pub: b64.enc(kp.pub) }));
  }

  /** Einen eigenen One-Time-Prekey anhand seiner ID verbrauchen (Responder-
   *  Seite). Liefert null, wenn er nicht (mehr) vorhanden ist — etwa weil
   *  er bereits verwendet wurde; der Handshake faellt dann automatisch auf
   *  die 2-DH-Variante zurueck (siehe crypto/ratchet.ts). */
  private consumeOneTimePrekey(id: string): KeyPair | undefined {
    const kp = this.oneTimePrekeys.get(id);
    if (!kp) return undefined;
    this.oneTimePrekeys.delete(id);
    return kp;
  }

  /** Sitzung zu einem Kontakt vollständig verwerfen ("Sitzung verbrennen").
   *  Danach ist ein komplett neuer Handshake nötig, falls man wieder
   *  Kontakt aufnimmt — es bleibt nichts von der alten Sitzung übrig. */
  dropSession(peerId: string): void {
    this.ratchets.delete(peerId);
    this.pendingHandshake.delete(peerId);
    const tag = this.sessionTags.get(peerId);
    if (tag) this.tagToPeer.delete(tag);
    this.sessionTags.delete(peerId);
  }

  /** Wir sind Initiator (Alice): Kontakt wurde gerade per Lookup gefunden.
   *  theirOtpk kommt aus einem Lookup mit forHandshake=true (net/client.ts)
   *  — der Relay hat diesen One-Time-Prekey bereits aus seinem Bestand
   *  entfernt, er wird also garantiert kein zweites Mal ausgegeben. */
  beginSession(myIdentity: Identity, contact: Contact, theirOtpk?: { id: string; pub: string }): void {
    const myX: KeyPair = { priv: b64.dec(myIdentity.xPriv), pub: b64.dec(myIdentity.xPub) };
    const theirPrekeyPub = b64.dec(contact.prekeyPub);
    const { sk, ephPub, pqCipherText } = handshakeInitiator(
      myX, b64.dec(contact.xPub), theirPrekeyPub, b64.dec(contact.pqPrekeyPub),
      theirOtpk ? b64.dec(theirOtpk.pub) : undefined
    );
    const ratchet = Ratchet.initAlice(sk, theirPrekeyPub);
    this.ratchets.set(contact.userId, ratchet);
    this.pendingHandshake.set(contact.userId, {
      ephPub: b64.enc(ephPub), pqCt: b64.enc(pqCipherText), otpkId: theirOtpk?.id,
    });
    const tag = deriveSessionTag(sk);
    this.sessionTags.set(contact.userId, tag);
    this.tagToPeer.set(tag, contact.userId);
  }

  /** Wir sind Responder (Bob): erste Nachricht eines (noch) unbekannten Kontakts kam an. */
  async acceptFirstMessage(myIdentity: Identity, peerUserId: string, envelope: Envelope): Promise<Uint8Array> {
    if (!envelope.x3dh || !envelope.header) throw new Error('Kein gültiger Erstkontakt-Envelope');
    const myX: KeyPair = { priv: b64.dec(myIdentity.xPriv), pub: b64.dec(myIdentity.xPub) };
    const myPrekey: KeyPair = { priv: b64.dec(myIdentity.prekeyPriv), pub: b64.dec(myIdentity.prekeyPub) };
    const myPqPrekeySecret = b64.dec(myIdentity.pqPrekeyPriv);
    const myOtpk = envelope.x3dh.otpkId ? this.consumeOneTimePrekey(envelope.x3dh.otpkId) : undefined;
    const sk = handshakeResponder(
      myX, myPrekey, b64.dec(envelope.x3dh.identityPub), b64.dec(envelope.x3dh.ephPub),
      myPqPrekeySecret, b64.dec(envelope.x3dh.pqCt), myOtpk
    );
    const ratchet = Ratchet.initBob(sk, myPrekey);
    const plaintext = unpadFromTier(await ratchet.decrypt({ header: envelope.header, ct: envelope.ct }));
    this.ratchets.set(peerUserId, ratchet);
    // Dasselbe sk liegt jetzt auf beiden Seiten vor -> identisches Tag,
    // ohne dass dafuer ein weiterer Nachrichtenaustausch noetig waere.
    const tag = deriveSessionTag(sk);
    this.sessionTags.set(peerUserId, tag);
    this.tagToPeer.set(tag, peerUserId);
    return plaintext;
  }

  /** 1:1-Nachricht verschlüsseln; hängt beim allerersten Mal den Handshake an.
   *  `tag` wird ab der allerersten Nachricht mitgeschickt (siehe
   *  deriveSessionTag oben) — der Relay ignoriert x3dh-Erstkontakt-Nachrichten
   *  dafuer bewusst (Empfaenger kennt das Tag dort noch nicht), nutzt es aber
   *  ab der zweiten Nachricht statt der Konto-ID zum Routing. */
  async encryptDirect(
    peerUserId: string, myIdentity: Identity, plaintext: Uint8Array
  ): Promise<{
    ct: string; header: { dh: string; pn: number; n: number };
    x3dh?: { ephPub: string; identityPub: string; pqCt: string; otpkId?: string };
    tag?: string;
  }> {
    const ratchet = this.ratchets.get(peerUserId);
    if (!ratchet) throw new Error('Keine Sitzung mit diesem Kontakt');
    const enc = await ratchet.encrypt(padToTier(plaintext));
    const pending = this.pendingHandshake.get(peerUserId);
    if (pending) this.pendingHandshake.delete(peerUserId);
    return {
      ct: enc.ct, header: enc.header,
      x3dh: pending
        ? { ephPub: pending.ephPub, identityPub: myIdentity.xPub, pqCt: pending.pqCt, otpkId: pending.otpkId }
        : undefined,
      tag: this.sessionTags.get(peerUserId),
    };
  }

  /** 1:1-Nachricht entschlüsseln (Sitzung muss bereits existieren). */
  async decryptDirect(peerUserId: string, envelope: Envelope): Promise<Uint8Array> {
    const ratchet = this.ratchets.get(peerUserId);
    if (!ratchet || !envelope.header) throw new Error('Keine Sitzung mit diesem Kontakt');
    return unpadFromTier(await ratchet.decrypt({ header: envelope.header, ct: envelope.ct }));
  }

  /** Cover-Traffic: erkennt eine entschlüsselte Dummy-Nachricht (nach dem
   *  Entpolstern) — siehe COVER_TRAFFIC_MARKER oben. Aufrufer (ui/App.tsx)
   *  verwirft die Nachricht daraufhin still (kein UI-Eintrag, kein Unread). */
  isCoverTraffic(plaintext: Uint8Array): boolean {
    return isCoverTrafficMarker(plaintext);
  }

  /** Klartext-Nutzlast für eine ausgehende Cover-Traffic-Nachricht — ganz
   *  normal über encryptDirect() wie jede echte Nachricht zu verschicken. */
  coverTrafficPlaintext(): Uint8Array {
    return COVER_TRAFFIC_MARKER;
  }

  /** Alle Peer-IDs mit bestehender 1:1-Sitzung — Kandidatenkreis für den
   *  zufälligen Cover-Traffic-Empfänger (nur an bereits bekannte Kontakte,
   *  siehe ui/App.tsx: scheduleCoverTraffic). */
  sessionPeerIds(): string[] {
    return [...this.ratchets.keys()];
  }

  /** Neuen Gruppenschlüssel erzeugen (Gruppe erstellen oder rotieren). */
  newGroupEpoch(chatId: string, prevEpoch: number): { epoch: number; fp: string } {
    const key = newGroupEpochKey();
    const epoch = prevEpoch + 1;
    this.groupKeys.set(chatId, { key, epoch });
    return { epoch, fp: groupFingerprint(key, epoch) };
  }

  /** Gruppenschlüssel aus einem empfangenen group-key-Envelope übernehmen. */
  applyGroupKey(chatId: string, keyB64: string, epoch: number): string {
    const key = b64.dec(keyB64);
    this.groupKeys.set(chatId, { key, epoch });
    return groupFingerprint(key, epoch);
  }

  currentGroupKeyB64(chatId: string): { key: string; epoch: number } | null {
    const g = this.groupKeys.get(chatId);
    return g ? { key: b64.enc(g.key), epoch: g.epoch } : null;
  }

  async encryptGroup(chatId: string, plaintext: Uint8Array): Promise<{ ct: string; epoch: number }> {
    const g = this.groupKeys.get(chatId);
    if (!g) throw new Error('Kein Gruppenschlüssel');
    const ct = await aesGcmEncrypt(g.key, padToTier(plaintext));
    return { ct: b64.enc(ct), epoch: g.epoch };
  }

  async decryptGroup(chatId: string, ct: string): Promise<Uint8Array> {
    const g = this.groupKeys.get(chatId);
    if (!g) throw new Error('Kein Gruppenschlüssel für diese Gruppe');
    return unpadFromTier(await aesGcmDecrypt(g.key, b64.dec(ct)));
  }
}

/** Ein Prozess = eine Engine-Instanz (analog zum RAM-Zustand von demo/seed.ts). */
export const realChat = new RealChatEngine();
