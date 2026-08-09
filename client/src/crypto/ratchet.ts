import {
  KeyPair, newX25519, dh, hkdfSha256, hmacSha256,
  aesGcmEncrypt, aesGcmDecrypt, b64, utf8, concat, rand,
} from './primitives';
import { pqDecapsulate, pqEncapsulate } from './pq';

const MAX_SKIP = 64;

export interface RatchetHeader {
  dh: string;
  pn: number;
  n: number;
}

export interface RatchetMessage {
  header: RatchetHeader;
  ct: string;
}

function kdfRk(rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const okm = hkdfSha256(dhOut, rk, 'RenkerVault-DoubleRatchet-RK', 64);
  return [okm.subarray(0, 32), okm.subarray(32, 64)];
}

function kdfCk(ck: Uint8Array): [Uint8Array, Uint8Array] {
  const next = hmacSha256(ck, new Uint8Array([2]));
  const mk = hmacSha256(ck, new Uint8Array([1]));
  return [next, mk];
}

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
  private dhs: KeyPair;
  private dhr: Uint8Array | null = null;
  private rk: Uint8Array;
  private cks: Uint8Array | null = null;
  private ckr: Uint8Array | null = null;
  private ns = 0; private nr = 0; private pn = 0;
  private skipped = new Map<string, Uint8Array>();

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

  static initAlice(sharedSecret: Uint8Array, theirRatchetPub: Uint8Array): Ratchet {
    const r = new Ratchet(sharedSecret, newX25519());
    r.dhr = theirRatchetPub;
    [r.rk, r.cks] = kdfRk(r.rk, dh(r.dhs.priv, r.dhr));
    return r;
  }

  static initBob(sharedSecret: Uint8Array, ownRatchet: KeyPair): Ratchet {
    return new Ratchet(sharedSecret, ownRatchet);
  }

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

  async decrypt(msg: RatchetMessage): Promise<Uint8Array> {
    const aad = utf8.enc(JSON.stringify(msg.header));
    const data = b64.dec(msg.ct);

    const skipKey = `${msg.header.dh}:${msg.header.n}`;
    const skippedMk = this.skipped.get(skipKey);
    if (skippedMk) {
      this.skipped.delete(skipKey);
      return aesGcmDecrypt(skippedMk, data, aad);
    }

    const theirDh = b64.dec(msg.header.dh);
    if (!this.dhr || b64.enc(this.dhr) !== msg.header.dh) {
      this.skipKeys(msg.header.pn);
      this.dhRatchet(theirDh);
    }

    this.skipKeys(msg.header.n);
    if (!this.ckr) throw new Error('Empfangskette nicht initialisiert');
    const [next, mk] = kdfCk(this.ckr);
    this.ckr = next;
    this.nr += 1;
    return aesGcmDecrypt(mk, data, aad);
  }

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

export function newGroupEpochKey(): Uint8Array { return rand(32); }
