/**
 * Safety Numbers / Schlüssel-Fingerprints (Schutz vor Man-in-the-Middle).
 * Wie bei Signal: beide Seiten sehen dieselbe Ziffernfolge und können sie
 * manuell (oder per QR) vergleichen. Ändert sich der Identity-Key eines
 * Kontakts, ändert sich die Safety Number -> UI warnt.
 */
import { sha256Bytes, concat, utf8, hex } from './primitives';

/**
 * 60-stellige Safety Number aus beiden Identity-Public-Keys.
 * Sortierung stellt sicher, dass beide Seiten dasselbe Ergebnis sehen.
 */
export function safetyNumber(pubA: Uint8Array, pubB: Uint8Array): string {
  const [x, y] = [pubA, pubB].sort((a, b) => hex(a).localeCompare(hex(b)));
  let digest = concat(utf8.enc('RenkerVault-SafetyNumber-v1'), x, y);
  // Iteriertes Hashing (erschwert Brute-Force auf schöne Fingerprints)
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

/** Kurzer Hex-Fingerprint (z. B. für Kopfzeile/HUD): "3F:A9:…" */
export function shortFingerprint(material: Uint8Array): string {
  const h = sha256Bytes(material);
  return [...h.subarray(0, 8)]
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
}

/** Fingerprint für Gruppen/Kanäle aus dem aktuellen Epoch-Key-Material. */
export function groupFingerprint(epochKey: Uint8Array, epoch: number): string {
  return shortFingerprint(concat(utf8.enc(`epoch:${epoch}`), epochKey));
}
