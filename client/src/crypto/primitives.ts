import { x25519, ed25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { argon2id } from 'hash-wasm';

export const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

export const b64 = {
  enc(u: Uint8Array): string {
    let s = '';
    const CH = 0x8000;
    for (let i = 0; i < u.length; i += CH) {
      s += String.fromCharCode(...u.subarray(i, i + CH));
    }
    return btoa(s);
  },
  dec(s: string): Uint8Array {
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  },
};

export const hex = (u: Uint8Array): string =>
  [...u].map((x) => x.toString(16).padStart(2, '0')).join('');

export const utf8 = {
  enc: (s: string): Uint8Array => new TextEncoder().encode(s),
  dec: (u: Uint8Array): string => new TextDecoder().decode(u),
};

export function concat(...arrs: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

export interface KeyPair { priv: Uint8Array; pub: Uint8Array; }

export function newX25519(): KeyPair {
  const priv = x25519.utils.randomPrivateKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}

export function newEd25519(): KeyPair {
  const priv = ed25519.utils.randomPrivateKey();
  return { priv, pub: ed25519.getPublicKey(priv) };
}

export const dh = (priv: Uint8Array, pub: Uint8Array): Uint8Array =>
  x25519.getSharedSecret(priv, pub);

export const edSign = (msg: Uint8Array, priv: Uint8Array): Uint8Array =>
  ed25519.sign(msg, priv);

export const sha256Bytes = (data: Uint8Array): Uint8Array => sha256(data);

export const hmacSha256 = (key: Uint8Array, data: Uint8Array): Uint8Array =>
  hmac(sha256, key, data);

export const hkdfSha256 = (
  ikm: Uint8Array, salt: Uint8Array, info: string, len: number
): Uint8Array => hkdf(sha256, ikm, salt, utf8.enc(info), len);

export async function aesGcmEncrypt(
  key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array
): Promise<Uint8Array> {
  const iv = rand(12);
  const k = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-GCM', false, ['encrypt']);
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource };
  if (aad) params.additionalData = aad as BufferSource;
  const ct = new Uint8Array(await crypto.subtle.encrypt(params, k, plaintext as BufferSource));
  return concat(iv, ct);
}

export async function aesGcmDecrypt(
  key: Uint8Array, data: Uint8Array, aad?: Uint8Array
): Promise<Uint8Array> {
  const iv = data.subarray(0, 12);
  const ct = data.subarray(12);
  const k = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-GCM', false, ['decrypt']);
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource };
  if (aad) params.additionalData = aad as BufferSource;
  return new Uint8Array(await crypto.subtle.decrypt(params, k, ct as BufferSource));
}

export const ARGON2 = { iterations: 4, memorySizeKiB: 64 * 1024, parallelism: 1 };

export async function deriveKey(passphrase: string, salt: Uint8Array): Promise<Uint8Array> {
  return argon2id({
    password: passphrase,
    salt,
    iterations: ARGON2.iterations,
    memorySize: ARGON2.memorySizeKiB,
    parallelism: ARGON2.parallelism,
    hashLength: 32,
    outputType: 'binary',
  });
}

export function constEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
