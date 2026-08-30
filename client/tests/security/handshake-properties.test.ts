// Property-based tests for the X3DH-lite + ML-KEM-768 hybrid handshake (fast-check).
// Asserts the invariants over arbitrary key material: initiator and responder always
// agree, agreement is bound to every input (change one → different key), and the PQ
// KEM round-trips while a tampered ciphertext degrades to a different secret rather
// than a matching one.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { b64, newX25519 } from '../../src/crypto/primitives';
import { newPqKeyPair, pqDecapsulate, pqEncapsulate } from '../../src/crypto/pq';
import { handshakeInitiator, handshakeResponder } from '../../src/crypto/ratchet';

function makeParty() {
  return { identity: newX25519(), prekey: newX25519(), pq: newPqKeyPair() };
}

// fast-check regenerates real key material for every run via a no-arg arbitrary.
const party = () => fc.constant(null).map(makeParty);
const otpk = () => fc.constant(null).map(() => newX25519());

describe('Hybrid handshake — property: initiator and responder agree', () => {
  it('derive the identical session key for arbitrary parties (lite and full)', () => {
    fc.assert(
      fc.property(party(), party(), fc.option(otpk(), { nil: undefined }), (alice, bob, one) => {
        const { sk, ephPub, pqCipherText } = handshakeInitiator(
          alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey, one?.pub,
        );
        const bobSk = handshakeResponder(
          bob.identity, bob.prekey, alice.identity.pub, ephPub,
          bob.pq.secretKey, pqCipherText, one ?? undefined,
        );
        expect(b64.enc(sk)).toBe(b64.enc(bobSk));
      }),
      { numRuns: 20 },
    );
  });
});

describe('Hybrid handshake — property: agreement is bound to every input', () => {
  it('changing any single responder key yields a different session key', () => {
    fc.assert(
      fc.property(
        party(),
        party(),
        fc.constantFrom<'identity' | 'prekey' | 'pq'>('identity', 'prekey', 'pq'),
        (alice, bob, which) => {
          const real = handshakeInitiator(
            alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey,
          );
          const other = makeParty();
          const swapped = {
            identity: which === 'identity' ? other.identity.pub : bob.identity.pub,
            prekey: which === 'prekey' ? other.prekey.pub : bob.prekey.pub,
            pq: which === 'pq' ? other.pq.publicKey : bob.pq.publicKey,
          };
          const spoofed = handshakeInitiator(
            alice.identity, swapped.identity, swapped.prekey, swapped.pq,
          );
          expect(b64.enc(real.sk)).not.toBe(b64.enc(spoofed.sk));
        },
      ),
      { numRuns: 20 },
    );
  });

  it('full X3DH (with one-time prekey) never collides with lite X3DH', () => {
    fc.assert(
      fc.property(party(), party(), otpk(), (alice, bob, one) => {
        const full = handshakeInitiator(
          alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey, one.pub,
        );
        const lite = handshakeInitiator(
          alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey,
        );
        expect(b64.enc(full.sk)).not.toBe(b64.enc(lite.sk));
      }),
      { numRuns: 15 },
    );
  });
});

describe('Hybrid handshake — property: ML-KEM-768 round-trip and reject', () => {
  it('decapsulation recovers the encapsulated secret for arbitrary keypairs', () => {
    fc.assert(
      fc.property(fc.constant(null).map(() => newPqKeyPair()), (kp) => {
        const { cipherText, sharedSecret } = pqEncapsulate(kp.publicKey);
        expect(b64.enc(pqDecapsulate(cipherText, kp.secretKey))).toBe(b64.enc(sharedSecret));
      }),
      { numRuns: 15 },
    );
  });

  it('a tampered ciphertext decapsulates to a different secret without throwing (implicit reject)', () => {
    fc.assert(
      fc.property(
        fc.constant(null).map(() => newPqKeyPair()),
        fc.nat(),
        (kp: ReturnType<typeof newPqKeyPair>, flip: number) => {
          const { cipherText, sharedSecret } = pqEncapsulate(kp.publicKey);
          const corrupted = cipherText.slice();
          corrupted[flip % corrupted.length] ^= 0xff;
          // FIPS 203 implicit rejection: no error, but a deterministically different secret,
          // so the first AEAD-protected ratchet message will fail rather than build a
          // silently mismatched session.
          const rejected = pqDecapsulate(corrupted, kp.secretKey);
          expect(b64.enc(rejected)).not.toBe(b64.enc(sharedSecret));
        },
      ),
      { numRuns: 15 },
    );
  });
});
