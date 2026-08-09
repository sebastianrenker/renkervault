import { sha256Bytes, concat, utf8, hex } from './primitives';

export function safetyNumber(pubA: Uint8Array, pubB: Uint8Array): string {
  const [x, y] = [pubA, pubB].sort((a, b) => hex(a).localeCompare(hex(b)));
  let digest = concat(utf8.enc('RenkerVault-SafetyNumber-v1'), x, y);
  for (let i = 0; i < 512; i++) digest = sha256Bytes(digest);

  let digits = '';
  for (let i = 0; digits.length < 60; i += 4) {
    const n =
      ((digest[i % 32] << 24) | (digest[(i + 1) % 32] << 16) |
       (digest[(i + 2) % 32] << 8) | digest[(i + 3) % 32]) >>> 0;
    digits += String(n % 100000).padStart(5, '0');
    if (digits.length % 32 === 0) digest = sha256Bytes(digest);
  }
  return digits.slice(0, 60).match(/.{5}/g)!.join(' ');
}

export function shortFingerprint(material: Uint8Array): string {
  const h = sha256Bytes(material);
  return [...h.subarray(0, 8)]
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
}

export function groupFingerprint(epochKey: Uint8Array, epoch: number): string {
  return shortFingerprint(concat(utf8.enc(`epoch:${epoch}`), epochKey));
}
