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

interface RatchetState {
  dhs: KeyPair;
  dhr: Uint8Array | null;
  rk: Uint8Array;
  cks: Uint8Array | null;
  ckr: Uint8Array | null;
  ns: number; nr: number; pn: number;
  skipped: Map<string, Uint8Array>;
}

function cloneState(s: RatchetState): RatchetState {
  return {
    dhs: { priv: s.dhs.priv.slice(), pub: s.dhs.pub.slice() },
    dhr: s.dhr ? s.dhr.slice() : null,
    rk: s.rk.slice(),
    cks: s.cks ? s.cks.slice() : null,
    ckr: s.ckr ? s.ckr.slice() : null,
    ns: s.ns, nr: s.nr, pn: s.pn,
    skipped: new Map(s.skipped),
  };
}

// Operiert auf einem Entwurf (draft), niemals direkt auf dem committeten State —
// Aufrufer (decrypt) verwirft den draft bei Fehlschlag, statt ihn zu übernehmen.
function skipMessageKeysInto(state: RatchetState, until: number): void {
  if (!state.ckr) return;
  if (state.nr + MAX_SKIP < until) throw new Error('Zu viele übersprungene Nachrichten');
  while (state.nr < until) {
    const [next, mk] = kdfCk(state.ckr);
    state.ckr = next;
    state.skipped.set(`${b64.enc(state.dhr!)}:${state.nr}`, mk);
    state.nr += 1;
    if (state.skipped.size > MAX_SKIP) {
      const first = state.skipped.keys().next().value as string;
      state.skipped.delete(first);
    }
  }
}

function dhRatchetInto(state: RatchetState, theirDh: Uint8Array): void {
  state.pn = state.ns;
  state.ns = 0;
  state.nr = 0;
  state.dhr = theirDh;
  [state.rk, state.ckr] = kdfRk(state.rk, dh(state.dhs.priv, state.dhr));
  state.dhs = newX25519();
  [state.rk, state.cks] = kdfRk(state.rk, dh(state.dhs.priv, state.dhr));
}

export class Ratchet {
  private state: RatchetState;
  // Serialisiert encrypt()/decrypt() auf dieser Instanz. Ohne das würden
  // überlappende Aufrufe (z. B. paralleles Senden, oder ein Send während ein
  // Deliver verarbeitet wird) denselben Kettenschlüssel doppelt lesen, bevor
  // der erste Aufruf committet — Message-Key-Wiederverwendung.
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(rk: Uint8Array, dhs: KeyPair) {
    this.state = {
      dhs, dhr: null, rk, cks: null, ckr: null,
      ns: 0, nr: 0, pn: 0, skipped: new Map(),
    };
  }

  private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.then(() => undefined, () => undefined);
    return run;
  }

  toSnapshot(): RatchetSnapshot {
    const s = this.state;
    return {
      dhsPriv: b64.enc(s.dhs.priv), dhsPub: b64.enc(s.dhs.pub),
      dhr: s.dhr ? b64.enc(s.dhr) : null,
      rk: b64.enc(s.rk),
      cks: s.cks ? b64.enc(s.cks) : null,
      ckr: s.ckr ? b64.enc(s.ckr) : null,
      ns: s.ns, nr: s.nr, pn: s.pn,
      skipped: [...s.skipped].map(([k, v]) => [k, b64.enc(v)]),
    };
  }

  static fromSnapshot(s: RatchetSnapshot): Ratchet {
    const r = new Ratchet(b64.dec(s.rk), { priv: b64.dec(s.dhsPriv), pub: b64.dec(s.dhsPub) });
    r.state.dhr = s.dhr ? b64.dec(s.dhr) : null;
    r.state.cks = s.cks ? b64.dec(s.cks) : null;
    r.state.ckr = s.ckr ? b64.dec(s.ckr) : null;
    r.state.ns = s.ns; r.state.nr = s.nr; r.state.pn = s.pn;
    r.state.skipped = new Map(s.skipped.map(([k, v]) => [k, b64.dec(v)]));
    return r;
  }

  static initAlice(sharedSecret: Uint8Array, theirRatchetPub: Uint8Array): Ratchet {
    const r = new Ratchet(sharedSecret, newX25519());
    r.state.dhr = theirRatchetPub;
    [r.state.rk, r.state.cks] = kdfRk(r.state.rk, dh(r.state.dhs.priv, r.state.dhr));
    return r;
  }

  static initBob(sharedSecret: Uint8Array, ownRatchet: KeyPair): Ratchet {
    return new Ratchet(sharedSecret, ownRatchet);
  }

  async encrypt(plaintext: Uint8Array): Promise<RatchetMessage> {
    return this.runExclusive(() => this.doEncrypt(plaintext));
  }

  async decrypt(msg: RatchetMessage): Promise<Uint8Array> {
    return this.runExclusive(() => this.doDecrypt(msg));
  }

  private async doEncrypt(plaintext: Uint8Array): Promise<RatchetMessage> {
    const s = this.state;
    if (!s.cks) throw new Error('Sendekette nicht initialisiert');
    const [next, mk] = kdfCk(s.cks);
    const header: RatchetHeader = { dh: b64.enc(s.dhs.pub), pn: s.pn, n: s.ns };
    const aad = utf8.enc(JSON.stringify(header));
    const ct = await aesGcmEncrypt(mk, plaintext, aad);
    // Sendekette erst nach erfolgreicher Verschlüsselung fortschreiben.
    s.cks = next;
    s.ns += 1;
    return { header, ct: b64.enc(ct) };
  }

  // Entschlüsselt gegen einen Entwurf des States und committet ihn nur bei Erfolg.
  // Verhindert, dass gefälschte/duplizierte/malformte Nachrichten (z. B. von einem
  // böswilligen Relay) die Ratchet-Kette durch einen fehlgeschlagenen Zustandsübergang
  // dauerhaft zerstören — siehe Signal-Spec RatchetDecrypt (state = deepcopy vor Versuch).
  private async doDecrypt(msg: RatchetMessage): Promise<Uint8Array> {
    const aad = utf8.enc(JSON.stringify(msg.header));
    const data = b64.dec(msg.ct);

    const skipKey = `${msg.header.dh}:${msg.header.n}`;
    const skippedMk = this.state.skipped.get(skipKey);
    if (skippedMk) {
      const plaintext = await aesGcmDecrypt(skippedMk, data, aad);
      this.state.skipped.delete(skipKey);
      return plaintext;
    }

    const draft = cloneState(this.state);
    const theirDh = b64.dec(msg.header.dh);
    if (!draft.dhr || b64.enc(draft.dhr) !== msg.header.dh) {
      skipMessageKeysInto(draft, msg.header.pn);
      dhRatchetInto(draft, theirDh);
    }

    skipMessageKeysInto(draft, msg.header.n);
    if (!draft.ckr) throw new Error('Empfangskette nicht initialisiert');
    const [next, mk] = kdfCk(draft.ckr);

    const plaintext = await aesGcmDecrypt(mk, data, aad);

    draft.ckr = next;
    draft.nr += 1;
    this.state = draft;
    return plaintext;
  }

  get publicKey(): Uint8Array { return this.state.dhs.pub; }
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
