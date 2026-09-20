import { describe, it, expect } from 'vitest';
import { newX25519, b64 } from '../../src/crypto/primitives';
import { newPqKeyPair, pqDecapsulate } from '../../src/crypto/pq';
import { handshakeInitiator, handshakeResponder } from '../../src/crypto/ratchet';

function makeParty() {
  return { identity: newX25519(), prekey: newX25519(), pq: newPqKeyPair() };
}

describe('X3DH / ML-KEM-768 hybrid handshake', () => {
  it('initiator and responder derive identical sk (full X3DH with a one-time prekey)', () => {
    const alice = makeParty();
    const bob = makeParty();
    const otpk = newX25519();

    const { sk: aliceSk, ephPub, pqCipherText } = handshakeInitiator(
      alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey, otpk.pub
    );
    const bobSk = handshakeResponder(
      bob.identity, bob.prekey, alice.identity.pub, ephPub, bob.pq.secretKey, pqCipherText, otpk
    );
    expect(b64.enc(aliceSk)).toBe(b64.enc(bobSk));
  });

  it('initiator and responder derive identical sk (lite X3DH without a one-time prekey)', () => {
    const alice = makeParty();
    const bob = makeParty();

    const { sk: aliceSk, ephPub, pqCipherText } = handshakeInitiator(
      alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey
    );
    const bobSk = handshakeResponder(
      bob.identity, bob.prekey, alice.identity.pub, ephPub, bob.pq.secretKey, pqCipherText
    );
    expect(b64.enc(aliceSk)).toBe(b64.enc(bobSk));
  });

  it('domain separation: full and lite mode produce different sk from identical key material', () => {
    const alice = makeParty();
    const bob = makeParty();
    const otpk = newX25519();

    const full = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey, otpk.pub);
    const lite = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    expect(b64.enc(full.sk)).not.toBe(b64.enc(lite.sk));
  });

  it('key binding: a different responder identity changes the derived sk', () => {
    const alice = makeParty();
    const bob = makeParty();
    const mallory = makeParty();

    const real = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    const spoofed = handshakeInitiator(alice.identity, mallory.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    expect(b64.enc(real.sk)).not.toBe(b64.enc(spoofed.sk));
  });

  it('key binding: a different responder prekey changes the derived sk', () => {
    const alice = makeParty();
    const bob = makeParty();
    const otherPrekey = newX25519();

    const real = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    const spoofed = handshakeInitiator(alice.identity, bob.identity.pub, otherPrekey.pub, bob.pq.publicKey);
    expect(b64.enc(real.sk)).not.toBe(b64.enc(spoofed.sk));
  });

  it('responder with a wrong identity (man-in-the-middle) lands on a different sk than Alice', () => {
    const alice = makeParty();
    const bob = makeParty();
    const mallory = makeParty();

    const { sk: aliceSk, ephPub, pqCipherText } = handshakeInitiator(
      alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey
    );
    // Mallory does not have Bob's prekey/PQ prekey — she can only respond with her
    // own identity, which leads to a completely different DH1 term and thus sk.
    const malloryAsBobSk = handshakeResponder(
      mallory.identity, bob.prekey, alice.identity.pub, ephPub, bob.pq.secretKey, pqCipherText
    );
    expect(b64.enc(aliceSk)).not.toBe(b64.enc(malloryAsBobSk));
  });

  it('a tampered PQ ciphertext leads to an implicit KEM reject (no crash, but wrong sk)', () => {
    const alice = makeParty();
    const bob = makeParty();
    const { ephPub, pqCipherText } = handshakeInitiator(
      alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey
    );

    const tampered = pqCipherText.slice();
    tampered[0] ^= 0xff;

    // ML-KEM uses implicit rejection (FO transform) instead of an error —
    // the result is deliberately a deterministically wrong but valid-looking
    // secret. All that matters: no crash, and the result differs from the
    // real pqSecret, so that the AEAD check of the first ratchet message later
    // fails safely instead of silently building a wrong session.
    const real = pqDecapsulate(pqCipherText, bob.pq.secretKey);
    const rejected = pqDecapsulate(tampered, bob.pq.secretKey);
    expect(b64.enc(real)).not.toBe(b64.enc(rejected));
    void ephPub;
  });

  it('a tampered low-order DH public key is rejected by X25519 instead of producing a null secret', () => {
    const alice = makeParty();
    const bob = makeParty();
    // Known low-order point (0) — @noble/curves rejects it per the RFC 7748 recommendation.
    const lowOrderPoint = new Uint8Array(32);
    expect(() => handshakeInitiator(alice.identity, bob.identity.pub, lowOrderPoint, bob.pq.publicKey))
      .toThrow();
  });
});
