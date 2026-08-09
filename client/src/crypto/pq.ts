import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export interface PqKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export function newPqKeyPair(): PqKeyPair {
  const kp = ml_kem768.keygen();
  return { secretKey: kp.secretKey, publicKey: kp.publicKey };
}

export function pqEncapsulate(theirPublicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array } {
  return ml_kem768.encapsulate(theirPublicKey);
}

export function pqDecapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_kem768.decapsulate(cipherText, secretKey);
}
