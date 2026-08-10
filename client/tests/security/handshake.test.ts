import { describe, it, expect } from 'vitest';
import { newX25519, b64 } from '../../src/crypto/primitives';
import { newPqKeyPair, pqDecapsulate } from '../../src/crypto/pq';
import { handshakeInitiator, handshakeResponder } from '../../src/crypto/ratchet';

function makeParty() {
  return { identity: newX25519(), prekey: newX25519(), pq: newPqKeyPair() };
}

describe('X3DH / ML-KEM-768-Hybrid-Handshake', () => {
  it('Initiator und Responder leiten identisches sk her (full X3DH mit One-Time-Prekey)', () => {
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

  it('Initiator und Responder leiten identisches sk her (lite X3DH ohne One-Time-Prekey)', () => {
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

  it('Domain-Separation: full- und lite-Modus erzeugen bei identischem Schlüsselmaterial unterschiedliche sk', () => {
    const alice = makeParty();
    const bob = makeParty();
    const otpk = newX25519();

    const full = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey, otpk.pub);
    const lite = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    expect(b64.enc(full.sk)).not.toBe(b64.enc(lite.sk));
  });

  it('Key-Binding: eine andere Identity des Responders ändert das abgeleitete sk', () => {
    const alice = makeParty();
    const bob = makeParty();
    const mallory = makeParty();

    const real = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    const spoofed = handshakeInitiator(alice.identity, mallory.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    expect(b64.enc(real.sk)).not.toBe(b64.enc(spoofed.sk));
  });

  it('Key-Binding: ein anderer Prekey des Responders ändert das abgeleitete sk', () => {
    const alice = makeParty();
    const bob = makeParty();
    const otherPrekey = newX25519();

    const real = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    const spoofed = handshakeInitiator(alice.identity, bob.identity.pub, otherPrekey.pub, bob.pq.publicKey);
    expect(b64.enc(real.sk)).not.toBe(b64.enc(spoofed.sk));
  });

  it('Responder mit falscher Identity (Man-in-the-Middle) landet auf einem anderen sk als Alice', () => {
    const alice = makeParty();
    const bob = makeParty();
    const mallory = makeParty();

    const { sk: aliceSk, ephPub, pqCipherText } = handshakeInitiator(
      alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey
    );
    // Mallory besitzt bobs Prekey/PQ-Prekey nicht — sie kann nur mit ihrer eigenen
    // Identity antworten, was zu einem komplett anderen DH1-Term und damit sk führt.
    const malloryAsBobSk = handshakeResponder(
      mallory.identity, bob.prekey, alice.identity.pub, ephPub, bob.pq.secretKey, pqCipherText
    );
    expect(b64.enc(aliceSk)).not.toBe(b64.enc(malloryAsBobSk));
  });

  it('ein manipuliertes PQ-Ciphertext führt zu implizitem KEM-Reject (kein Crash, aber falsches sk)', () => {
    const alice = makeParty();
    const bob = makeParty();
    const { ephPub, pqCipherText } = handshakeInitiator(
      alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey
    );

    const tampered = pqCipherText.slice();
    tampered[0] ^= 0xff;

    // ML-KEM verwendet implizite Ablehnung (FO-Transform) statt eines Fehlers —
    // das Ergebnis ist bewusst ein deterministisch falsches, aber gültig aussehendes
    // Secret. Wichtig ist nur: kein Crash, und das Ergebnis unterscheidet sich vom
    // echten pqSecret, sodass die AEAD-Prüfung der ersten Ratchet-Nachricht später
    // sicher fehlschlägt statt eine falsche Sitzung unbemerkt aufzubauen.
    const real = pqDecapsulate(pqCipherText, bob.pq.secretKey);
    const rejected = pqDecapsulate(tampered, bob.pq.secretKey);
    expect(b64.enc(real)).not.toBe(b64.enc(rejected));
    void ephPub;
  });

  it('ein manipulierter DH-Public-Key mit niedriger Ordnung wird von X25519 abgelehnt statt eine Null-Secret zu erzeugen', () => {
    const alice = makeParty();
    const bob = makeParty();
    // Bekannter Low-Order-Punkt (0) — @noble/curves lehnt das laut RFC-7748-Empfehlung ab.
    const lowOrderPoint = new Uint8Array(32);
    expect(() => handshakeInitiator(alice.identity, bob.identity.pub, lowOrderPoint, bob.pq.publicKey))
      .toThrow();
  });
});
