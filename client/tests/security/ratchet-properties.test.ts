// Property-based tests for the Double Ratchet state machine (fast-check).
// The existing ratchet.test.ts pins specific scenarios; this file asserts the
// *invariants* that must hold for arbitrary plaintexts and delivery schedules —
// round-trip, out-of-order within the skip window, and tamper-rejection that
// never corrupts state.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { b64, hex, newX25519 } from '../../src/crypto/primitives';
import { newPqKeyPair } from '../../src/crypto/pq';
import {
  handshakeInitiator,
  handshakeResponder,
  Ratchet,
  RatchetMessage,
} from '../../src/crypto/ratchet';

const MAX_SKIP = 64; // must match the constant in ratchet.ts

function makeParty() {
  return { identity: newX25519(), prekey: newX25519(), pq: newPqKeyPair() };
}

function establishSession(): { alice: Ratchet; bob: Ratchet } {
  const alice = makeParty();
  const bob = makeParty();
  const { sk: aliceSk, ephPub, pqCipherText } = handshakeInitiator(
    alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey,
  );
  const bobSk = handshakeResponder(
    bob.identity, bob.prekey, alice.identity.pub, ephPub, bob.pq.secretKey, pqCipherText,
  );
  return {
    alice: Ratchet.initAlice(aliceSk, bob.prekey.pub),
    bob: Ratchet.initBob(bobSk, bob.prekey),
  };
}

describe('Double Ratchet — property: round-trip', () => {
  it('decrypts arbitrary plaintexts back to the original, in order', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.uint8Array({ minLength: 0, maxLength: 200 }), { minLength: 1, maxLength: 25 }),
        async (messages) => {
          const { alice, bob } = establishSession();
          for (const plaintext of messages) {
            const msg = await alice.encrypt(plaintext);
            expect(hex(await bob.decrypt(msg))).toBe(hex(plaintext));
          }
        },
      ),
      { numRuns: 25 },
    );
  });

  it('stays correct under alternating send direction', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.tuple(fc.boolean(), fc.uint8Array({ maxLength: 64 })), { maxLength: 30 }),
        async (turns) => {
          const { alice, bob } = establishSession();
          // Bob can only send after receiving Alice's first message (derives his CKs).
          const init = await alice.encrypt(new Uint8Array([1]));
          await bob.decrypt(init);
          for (const [fromAlice, plaintext] of turns) {
            const [sender, receiver] = fromAlice ? [alice, bob] : [bob, alice];
            const msg = await sender.encrypt(plaintext);
            expect(hex(await receiver.decrypt(msg))).toBe(hex(plaintext));
          }
        },
      ),
      { numRuns: 20 },
    );
  });
});

describe('Double Ratchet — property: out-of-order within the skip window', () => {
  it('any delivery permutation of a single chain decrypts each message exactly once', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc
          .integer({ min: 1, max: MAX_SKIP })
          .chain((n) =>
            fc.record({
              plaintexts: fc.array(fc.uint8Array({ maxLength: 32 }), { minLength: n, maxLength: n }),
              order: fc.shuffledSubarray([...Array(n).keys()], { minLength: n, maxLength: n }),
            }),
          ),
        async ({ plaintexts, order }) => {
          const { alice, bob } = establishSession();
          const sent: RatchetMessage[] = [];
          for (const p of plaintexts) sent.push(await alice.encrypt(p));
          for (const i of order) {
            expect(hex(await bob.decrypt(sent[i]))).toBe(hex(plaintexts[i]));
          }
        },
      ),
      { numRuns: 20 },
    );
  });
});

describe('Double Ratchet — property: tamper rejection preserves state', () => {
  it('any single-byte flip in the ciphertext is rejected, and the genuine message still decrypts', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 128 }),
        fc.nat(),
        async (plaintext, flipIndex) => {
          const { alice, bob } = establishSession();
          const msg = await alice.encrypt(plaintext);
          const raw = b64.dec(msg.ct);
          const pos = flipIndex % raw.length;
          const corrupted = raw.slice();
          corrupted[pos] ^= 0xff;
          const tampered: RatchetMessage = { header: msg.header, ct: b64.enc(corrupted) };

          await expect(bob.decrypt(tampered)).rejects.toThrow();
          // The failed attempt must not have advanced Bob's receive chain.
          expect(hex(await bob.decrypt(msg))).toBe(hex(plaintext));
        },
      ),
      { numRuns: 25 },
    );
  });

  it('replaying an already-delivered message is always rejected, later messages unaffected', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.uint8Array({ maxLength: 32 }), { minLength: 2, maxLength: 12 }),
        async (plaintexts) => {
          const { alice, bob } = establishSession();
          const sent: RatchetMessage[] = [];
          for (const p of plaintexts) sent.push(await alice.encrypt(p));

          // Deliver the first, replay it (must reject), then the rest must still work.
          expect(hex(await bob.decrypt(sent[0]))).toBe(hex(plaintexts[0]));
          await expect(bob.decrypt(sent[0])).rejects.toThrow();
          for (let i = 1; i < sent.length; i++) {
            expect(hex(await bob.decrypt(sent[i]))).toBe(hex(plaintexts[i]));
          }
        },
      ),
      { numRuns: 20 },
    );
  });
});
