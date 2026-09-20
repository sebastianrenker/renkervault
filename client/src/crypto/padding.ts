export const PAD_TIERS = [
  64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 1310720,
] as const;

export function padToTier(plaintext: Uint8Array): Uint8Array {
  const needed = plaintext.length + 1;
  const tier = PAD_TIERS.find((t) => t >= needed);
  if (tier === undefined) {
    throw new Error(
      `payload too large to pad (${plaintext.length} bytes, largest tier ${PAD_TIERS[PAD_TIERS.length - 1]} bytes)`
    );
  }
  const out = new Uint8Array(tier);
  out.set(plaintext, 0);
  out[plaintext.length] = 0x80;
  return out;
}

export function unpadFromTier(padded: Uint8Array): Uint8Array {
  let i = padded.length - 1;
  while (i >= 0 && padded[i] === 0x00) i--;
  if (i < 0 || padded[i] !== 0x80) {
    throw new Error('invalid padding — data corrupted or not padded');
  }
  return padded.subarray(0, i);
}
