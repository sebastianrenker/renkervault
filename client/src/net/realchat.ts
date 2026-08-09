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

const OTPK_LOW_WATERMARK = 15;
const OTPK_TARGET = 25;
const OTPK_MAX_STORE = 60;

function deriveSessionTag(sk: Uint8Array): string {
  return hex(hkdfSha256(sk, new Uint8Array(32), 'RenkerVault-SealedSender-Tag', 16));
}

const COVER_TRAFFIC_MARKER = sha256Bytes(utf8.enc('RenkerVault-CoverTraffic-v1'));

function isCoverTrafficMarker(plaintext: Uint8Array): boolean {
  if (plaintext.length !== COVER_TRAFFIC_MARKER.length) return false;
  let diff = 0;
  for (let i = 0; i < plaintext.length; i++) diff |= plaintext[i] ^ COVER_TRAFFIC_MARKER[i];
  return diff === 0;
}

class RealChatEngine {
  private ratchets = new Map<string, Ratchet>();
  private pendingHandshake = new Map<string, { ephPub: string; pqCt: string; otpkId?: string }>();
  private groupKeys = new Map<string, { key: Uint8Array; epoch: number }>();
  private oneTimePrekeys = new Map<string, KeyPair>();
  private sessionTags = new Map<string, string>();
  private tagToPeer = new Map<string, string>();

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
    }
    for (const [chatId, g] of Object.entries(groupKeys)) {
      this.groupKeys.set(chatId, { key: b64.dec(g.key), epoch: g.epoch });
    }
    for (const [id, kp] of Object.entries(oneTimePrekeys)) {
      this.oneTimePrekeys.set(id, { priv: b64.dec(kp.priv), pub: b64.dec(kp.pub) });
    }
  }

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

  resolvePeerByTag(tag: string): string | undefined {
    return this.tagToPeer.get(tag);
  }

  snapshotGroupKeys(): Record<string, { key: string; epoch: number }> {
    const out: Record<string, { key: string; epoch: number }> = {};
    for (const [chatId, g] of this.groupKeys) out[chatId] = { key: b64.enc(g.key), epoch: g.epoch };
    return out;
  }

  snapshotOneTimePrekeys(): Record<string, { priv: string; pub: string }> {
    const out: Record<string, { priv: string; pub: string }> = {};
    for (const [id, kp] of this.oneTimePrekeys) out[id] = { priv: b64.enc(kp.priv), pub: b64.enc(kp.pub) };
    return out;
  }

  hasSession(peerId: string): boolean { return this.ratchets.has(peerId); }

  oneTimePrekeyCount(): number { return this.oneTimePrekeys.size; }

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

  publishableOneTimePrekeys(): { id: string; pub: string }[] {
    return [...this.oneTimePrekeys].map(([id, kp]) => ({ id, pub: b64.enc(kp.pub) }));
  }

  private consumeOneTimePrekey(id: string): KeyPair | undefined {
    const kp = this.oneTimePrekeys.get(id);
    if (!kp) return undefined;
    this.oneTimePrekeys.delete(id);
    return kp;
  }

  dropSession(peerId: string): void {
    this.ratchets.delete(peerId);
    this.pendingHandshake.delete(peerId);
    const tag = this.sessionTags.get(peerId);
    if (tag) this.tagToPeer.delete(tag);
    this.sessionTags.delete(peerId);
  }

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
    const tag = deriveSessionTag(sk);
    this.sessionTags.set(peerUserId, tag);
    this.tagToPeer.set(tag, peerUserId);
    return plaintext;
  }

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

  async decryptDirect(peerUserId: string, envelope: Envelope): Promise<Uint8Array> {
    const ratchet = this.ratchets.get(peerUserId);
    if (!ratchet || !envelope.header) throw new Error('Keine Sitzung mit diesem Kontakt');
    return unpadFromTier(await ratchet.decrypt({ header: envelope.header, ct: envelope.ct }));
  }

  isCoverTraffic(plaintext: Uint8Array): boolean {
    return isCoverTrafficMarker(plaintext);
  }

  coverTrafficPlaintext(): Uint8Array {
    return COVER_TRAFFIC_MARKER;
  }

  sessionPeerIds(): string[] {
    return [...this.ratchets.keys()];
  }

  newGroupEpoch(chatId: string, prevEpoch: number): { epoch: number; fp: string } {
    const key = newGroupEpochKey();
    const epoch = prevEpoch + 1;
    this.groupKeys.set(chatId, { key, epoch });
    return { epoch, fp: groupFingerprint(key, epoch) };
  }

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

export const realChat = new RealChatEngine();
