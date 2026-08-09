/**
 * Nachrichten-Padding auf feste Größenstufen (Härtungs-Roadmap Punkt 4,
 * siehe docs/inventions/RenkerVault-Haertungs-Roadmap.md).
 * =============================================================
 * KEINE kryptografische Primitive — reine Byte-Manipulation auf bereits
 * fertigem Klartext, VOR der eigentlichen AES-GCM-Verschlüsselung in
 * net/realchat.ts angewendet. Ziel: Der Relay sieht nur noch die
 * Chiffretext-GRÖSSE (eine von wenigen festen Stufen), nicht mehr die
 * exakte Klartextlänge — ohne das ist z. B. sofort erkennbar, ob eine
 * Nachricht "ok" (2 Zeichen) oder ein langer Text war, selbst ohne den
 * Inhalt zu kennen. Ergänzt NICHT den Timing-Kanal (dafür siehe die
 * Cover-Traffic-Logik in net/realchat.ts + ui/App.tsx) — Padding allein
 * verschleiert nur Größe, nicht Sendezeitpunkt/-häufigkeit.
 *
 * Schema: ISO/IEC 7816-4-artig (ein 0x80-Markerbyte direkt nach den
 * echten Daten, danach Nullbytes bis zur nächsten Größenstufe). Anders als
 * PKCS#7 ist die Padding-Länge hier nicht auf 255 Bytes begrenzt, was bei
 * großen Sprüngen zwischen den Stufen (z. B. 64 KiB -> 256 KiB) nötig ist.
 * Entpolstern läuft rückwärts vom Ende: erstes Nicht-Null-Byte MUSS 0x80
 * sein, sonst gilt der Puffer als beschädigt/nicht gepolstert.
 */

/** Größenstufen in Byte. Oberste Stufe deckt den größten erlaubten Anhang
 *  ab (MAX_FILE_BYTES = 1,2 MiB, siehe ui/App.tsx) plus Marker-Spielraum. */
export const PAD_TIERS = [
  64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 1310720,
] as const;

export function padToTier(plaintext: Uint8Array): Uint8Array {
  const needed = plaintext.length + 1; // +1 fuer das 0x80-Markerbyte
  const tier = PAD_TIERS.find((t) => t >= needed);
  if (tier === undefined) {
    throw new Error(
      `Nutzlast zu groß zum Padden (${plaintext.length} Byte, größte Stufe ${PAD_TIERS[PAD_TIERS.length - 1]} Byte)`
    );
  }
  const out = new Uint8Array(tier); // Uint8Array ist per Spezifikation nullinitialisiert
  out.set(plaintext, 0);
  out[plaintext.length] = 0x80;
  return out;
}

export function unpadFromTier(padded: Uint8Array): Uint8Array {
  let i = padded.length - 1;
  while (i >= 0 && padded[i] === 0x00) i--;
  if (i < 0 || padded[i] !== 0x80) {
    throw new Error('Padding ungültig — Daten beschädigt oder nicht gepolstert');
  }
  return padded.subarray(0, i);
}
