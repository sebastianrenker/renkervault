// Known-answer tests (KATs) pinning the crypto primitives to published standards.
// The existing suite proves the *protocol* behaves; these prove the *primitives*
// under it match the specs they claim to implement, so a dependency swap or a
// wrong parameter can never pass silently.
import { describe, expect, it } from 'vitest';

import { dh, hex, hkdfSha256, hmacSha256 } from '../../src/crypto/primitives';
import { newPqKeyPair, pqDecapsulate, pqEncapsulate } from '../../src/crypto/pq';

const fromHex = (s: string): Uint8Array =>
  Uint8Array.from(s.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));

describe('KAT — X25519 scalar multiplication (RFC 7748 §5.2)', () => {
  it('reproduces the published scalar/u-coordinate vector', () => {
    const scalar = fromHex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
    const u = fromHex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c');
    // dh() is X25519(scalar, u); the whole Double Ratchet rests on this being correct.
    expect(hex(dh(scalar, u))).toBe(
      'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
    );
  });
});

describe('KAT — HMAC-SHA-256 (RFC 4231 test case 1)', () => {
  it('reproduces the published digest', () => {
    const key = new Uint8Array(20).fill(0x0b);
    const data = new TextEncoder().encode('Hi There');
    // hmacSha256 is the chain-key KDF (kdfCk) under the ratchet.
    expect(hex(hmacSha256(key, data))).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    );
  });
});

describe('KAT — HKDF-SHA-256 (RFC 5869 test case 3)', () => {
  it('reproduces the published OKM for empty salt and info', () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    // hkdfSha256(ikm, salt, info, len) — the root-key KDF (kdfRk) under the ratchet.
    const okm = hkdfSha256(ikm, new Uint8Array(0), '', 42);
    expect(hex(okm)).toBe(
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    );
  });
});

describe('KAT — ML-KEM-768 (FIPS 203) via @noble/post-quantum', () => {
  it('encapsulate/decapsulate recover the identical shared secret', () => {
    const kp = newPqKeyPair();
    const { cipherText, sharedSecret } = pqEncapsulate(kp.publicKey);
    expect(hex(pqDecapsulate(cipherText, kp.secretKey))).toBe(hex(sharedSecret));
  });

  it('produces standards-sized ML-KEM-768 keys and ciphertext', () => {
    const kp = newPqKeyPair();
    const { cipherText } = pqEncapsulate(kp.publicKey);
    // FIPS 203 ML-KEM-768 fixed sizes — a wrong parameter set changes these.
    expect(kp.publicKey.length).toBe(1184);
    expect(kp.secretKey.length).toBe(2400);
    expect(cipherText.length).toBe(1088);
  });
});
