import { describe, it, expect } from 'vitest';
import { b64, edSign, newEd25519, newX25519 } from '../../src/crypto/primitives';
import { newPqKeyPair } from '../../src/crypto/pq';
import { RealChatEngine } from '../../src/net/realchat';
import type { Contact, Identity } from '../../src/state/types';

function makeIdentity(userId: string): Identity {
  const x = newX25519();
  const e = newEd25519();
  const prekey = newX25519();
  const pq = newPqKeyPair();
  return {
    userId, displayName: userId,
    xPriv: b64.enc(x.priv), xPub: b64.enc(x.pub),
    edPriv: b64.enc(e.priv), edPub: b64.enc(e.pub),
    prekeyPriv: b64.enc(prekey.priv), prekeyPub: b64.enc(prekey.pub),
    pqPrekeyPriv: b64.enc(pq.secretKey), pqPrekeyPub: b64.enc(pq.publicKey),
    prekeySig: b64.enc(edSign(prekey.pub, e.priv)),
    pqPrekeySig: b64.enc(edSign(pq.publicKey, e.priv)),
    deviceId: 'dev-1', deviceName: 'x',
  };
}

function contactFrom(identity: Identity): Contact {
  return {
    userId: identity.userId, name: identity.userId, edPub: identity.edPub, xPub: identity.xPub,
    prekeyPub: identity.prekeyPub, pqPrekeyPub: identity.pqPrekeyPub,
    prekeySig: identity.prekeySig, pqPrekeySig: identity.pqPrekeySig,
    addedAt: Date.now(), verified: false,
  };
}

describe('X3DH — Prekey-Signatur-Bindung (PREKEY-SIG)', () => {
  it('beginSession funktioniert normal mit korrekt signierten Prekeys', () => {
    const alice = makeIdentity('alice');
    const bob = makeIdentity('bob');
    const engine = new RealChatEngine();
    expect(() => engine.beginSession(alice, contactFrom(bob))).not.toThrow();
    expect(engine.hasSession('bob')).toBe(true);
  });

  it('lehnt einen vom Relay untergeschobenen fremden Prekey ab (Substitutionsangriff)', () => {
    const alice = makeIdentity('alice');
    const bob = makeIdentity('bob');
    const mallory = makeIdentity('mallory');
    const engine = new RealChatEngine();

    // Ein böswilliger Relay ersetzt Bobs echten Prekey durch Mallorys —
    // die Signatur stammt aber weiterhin (fälschlich) "von Bob" behauptet.
    const forgedContact = contactFrom(bob);
    forgedContact.prekeyPub = mallory.prekeyPub;

    expect(() => engine.beginSession(alice, forgedContact)).toThrow();
    expect(engine.hasSession('bob')).toBe(false);
  });

  it('lehnt einen untergeschobenen fremden PQ-Prekey ab', () => {
    const alice = makeIdentity('alice');
    const bob = makeIdentity('bob');
    const mallory = makeIdentity('mallory');
    const engine = new RealChatEngine();

    const forgedContact = contactFrom(bob);
    forgedContact.pqPrekeyPub = mallory.pqPrekeyPub;

    expect(() => engine.beginSession(alice, forgedContact)).toThrow();
  });

  it('lehnt einen Kontakt ohne jede Prekey-Signatur ab (kein stiller Fallback)', () => {
    const alice = makeIdentity('alice');
    const bob = makeIdentity('bob');
    const engine = new RealChatEngine();

    const unsigned = contactFrom(bob);
    unsigned.prekeySig = undefined;
    unsigned.pqPrekeySig = undefined;

    expect(() => engine.beginSession(alice, unsigned)).toThrow();
  });

  it('lehnt eine Signatur ab, die mit einem falschen Identitätsschlüssel erzeugt wurde', () => {
    const alice = makeIdentity('alice');
    const bob = makeIdentity('bob');
    const mallory = makeIdentity('mallory');
    const engine = new RealChatEngine();

    // Mallory signiert BOBs echten Prekey mit IHREM EIGENEN Identitätsschlüssel
    // und gibt sich als Bob aus (edPub bleibt Bobs echter Wert im Envelope-Feld).
    const spoofed = contactFrom(bob);
    spoofed.prekeySig = b64.enc(edSign(b64.dec(bob.prekeyPub), b64.dec(mallory.edPriv)));

    expect(() => engine.beginSession(alice, spoofed)).toThrow();
  });
});
