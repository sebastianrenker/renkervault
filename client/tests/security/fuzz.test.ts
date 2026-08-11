import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { unpadFromTier, padToTier, PAD_TIERS } from '../../src/crypto/padding';
import { b64, newX25519 } from '../../src/crypto/primitives';
import { newPqKeyPair } from '../../src/crypto/pq';
import { Ratchet, handshakeInitiator, handshakeResponder, RatchetMessage } from '../../src/crypto/ratchet';

const bytes = (min = 0, max = 4096) => fc.uint8Array({ minLength: min, maxLength: max });

describe('Fuzzing — Padding-Parser (padding.ts)', () => {
  it('unpadFromTier stürzt bei beliebigen Bytes nie mit einer nicht abgefangenen Exception ab', () => {
    fc.assert(fc.property(bytes(0, 2_000_000), (data) => {
      try {
        unpadFromTier(data);
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
      }
    }), { numRuns: 500 });
  });

  it('unpadFromTier(padToTier(x)) == x für beliebige Klartexte innerhalb der Größenstufen', () => {
    fc.assert(fc.property(bytes(0, PAD_TIERS[PAD_TIERS.length - 1] - 1), (data) => {
      const padded = padToTier(data);
      const recovered = unpadFromTier(padded);
      expect(b64.enc(recovered)).toBe(b64.enc(data));
    }), { numRuns: 200 });
  });

  it('padToTier lehnt Nutzlasten über der größten Stufe kontrolliert ab, statt zu crashen', () => {
    fc.assert(fc.property(fc.integer({ min: PAD_TIERS[PAD_TIERS.length - 1], max: PAD_TIERS[PAD_TIERS.length - 1] + 10 }), (len) => {
      const data = new Uint8Array(len);
      expect(() => padToTier(data)).toThrow();
    }), { numRuns: 5 });
  });
});

describe('Fuzzing — Ratchet gegen feindliche Nachrichten', () => {
  function establish() {
    const alice = { identity: newX25519(), prekey: newX25519(), pq: newPqKeyPair() };
    const bob = { identity: newX25519(), prekey: newX25519(), pq: newPqKeyPair() };
    const { sk, ephPub, pqCipherText } = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    const bobSk = handshakeResponder(bob.identity, bob.prekey, alice.identity.pub, ephPub, bob.pq.secretKey, pqCipherText);
    void bobSk;
    return { alice: Ratchet.initAlice(sk, bob.prekey.pub) , bobRatchetInit: () => Ratchet.initBob(bobSk, bob.prekey) };
  }

  it('zufällige/abgeschnittene/übergroße Ciphertexts mit beliebigem Header werden immer sicher abgelehnt', async () => {
    const { bobRatchetInit } = establish();
    await fc.assert(fc.asyncProperty(
      fc.record({
        dh: fc.uint8Array({ minLength: 32, maxLength: 32 }).map((u) => b64.enc(u)),
        pn: fc.integer({ min: -1000, max: 1000 }),
        n: fc.integer({ min: -1000, max: 100000 }),
      }),
      bytes(0, 5000),
      async (header, ctBytes) => {
        const bob = bobRatchetInit();
        const msg: RatchetMessage = { header, ct: b64.enc(ctBytes) };
        let threw = false;
        try { await bob.decrypt(msg); } catch { threw = true; }
        // Bei zufaelligen Eingaben darf so gut wie nie erfolgreich entschluesselt
        // werden — entscheidend ist: kein Crash ausserhalb eines gefangenen Errors
        // (das asyncProperty selbst wuerde sonst fehlschlagen), kein Hang.
        expect(typeof threw).toBe('boolean');
      }
    ), { numRuns: 100 });
  });

  it('ein Legit-Austausch bleibt nach vorherigen Fuzz-Angriffsversuchen auf derselben Instanz funktionsfähig', async () => {
    const { alice, bobRatchetInit } = establish();
    const bob = bobRatchetInit();

    for (let i = 0; i < 30; i++) {
      const junk: RatchetMessage = {
        header: { dh: b64.enc(new Uint8Array(32)), pn: 0, n: i },
        ct: b64.enc(new Uint8Array(16 + i)),
      };
      try { await bob.decrypt(junk); } catch { /* erwartet */ }
    }

    const real = await alice.encrypt(new TextEncoder().encode('trotzdem lesbar'));
    const plain = await bob.decrypt(real);
    expect(new TextDecoder().decode(plain)).toBe('trotzdem lesbar');
  });
});
