/**
 * Lokaler, verschlüsselter Vault (At-Rest-Verschlüsselung).
 * =========================================================
 * Der komplette lokale Zustand (Identität, Chats, Nachrichtenverlauf,
 * Einstellungen) liegt NIE im Klartext auf der Platte:
 *
 *   Passphrase --Argon2id--> KEK
 *   KEK  -- AES-256-GCM -->  wrappt einen zufälligen Master-Key
 *   Master-Key -- AES-256-GCM --> verschlüsselt den Datenblob
 *   HKDF(Master-Key,"mac") --> MAC-Key: HMAC-SHA256 über den Ciphertext
 *                              (Manipulationserkennung -> Alarm)
 *
 * Passwortwechsel = nur Re-Wrap des Master-Keys (Daten bleiben unberührt).
 * Duress-PIN: eigener Argon2id-Hash; die richtige PIN öffnet eine leere
 * Fake-Ansicht statt der echten Daten (Notfall-/Zwangs-Situationen).
 *
 * Speicherort im Prototyp: localStorage (Browser). In einer Tauri-/Desktop-
 * Variante wäre das eine SQLCipher-Datenbank — das Schlüsselmodell bleibt gleich.
 */
import {
  rand, b64, utf8, deriveKey, constEq,
  aesGcmEncrypt, aesGcmDecrypt, hkdfSha256, hmacSha256,
} from './primitives';

const LS_KEY = 'renkervault.vault.v1';

interface VaultFile {
  v: 1;
  createdAt: number;
  kdfSalt: string;                      // Salt für Argon2id (Passphrase)
  wrap: string;                         // AES-GCM(KEK, masterKey)
  duress: { salt: string; hash: string } | null;
  data: string;                         // AES-GCM(masterKey, JSON-Zustand)
  mac: string;                          // HMAC-SHA256(macKey, data-Ciphertext)
}

export type UnlockResult<T> =
  | { ok: true; duress: false; data: T }
  | { ok: true; duress: true }
  | { ok: false; reason: 'wrong-pass' | 'tampered' | 'missing' };

let masterKey: Uint8Array | null = null; // nur im RAM, nie persistiert

function macKeyOf(mk: Uint8Array): Uint8Array {
  return hkdfSha256(mk, new Uint8Array(32), 'RenkerVault-Vault-MAC', 32);
}

function readFile(): VaultFile | null {
  const raw = localStorage.getItem(LS_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw) as VaultFile; } catch { return null; }
}

export function vaultExists(): boolean { return readFile() !== null; }
export function hasDuressPin(): boolean { return readFile()?.duress != null; }
export function isUnlocked(): boolean { return masterKey !== null; }
export function lockVault(): void { masterKey = null; }

/** Vault anlegen: Master-Key erzeugen, mit Passphrase-KEK wrappen, Daten speichern. */
export async function createVault<T>(
  passphrase: string, duressPin: string | null, data: T
): Promise<void> {
  const kdfSalt = rand(16);
  const kek = await deriveKey(passphrase, kdfSalt);
  const mk = rand(32);
  const wrap = await aesGcmEncrypt(kek, mk);

  let duress: VaultFile['duress'] = null;
  if (duressPin) {
    const dSalt = rand(16);
    duress = { salt: b64.enc(dSalt), hash: b64.enc(await deriveKey(duressPin, dSalt)) };
  }

  masterKey = mk;
  const { data: ct, mac } = await sealData(data);
  const file: VaultFile = {
    v: 1, createdAt: Date.now(),
    kdfSalt: b64.enc(kdfSalt), wrap: b64.enc(wrap),
    duress, data: ct, mac,
  };
  localStorage.setItem(LS_KEY, JSON.stringify(file));
}

async function sealData<T>(data: T): Promise<{ data: string; mac: string }> {
  if (!masterKey) throw new Error('Vault ist gesperrt');
  const ct = await aesGcmEncrypt(masterKey, utf8.enc(JSON.stringify(data)));
  const mac = hmacSha256(macKeyOf(masterKey), ct);
  return { data: b64.enc(ct), mac: b64.enc(mac) };
}

/** Zustand neu verschlüsselt persistieren (nach jeder relevanten Änderung). */
export async function saveVault<T>(data: T): Promise<void> {
  const file = readFile();
  if (!file || !masterKey) return;
  const sealed = await sealData(data);
  file.data = sealed.data;
  file.mac = sealed.mac;
  localStorage.setItem(LS_KEY, JSON.stringify(file));
}

/**
 * Entsperren. Prüft zuerst die Duress-PIN (öffnet Fake-Ansicht),
 * dann die echte Passphrase inkl. Integritätsprüfung des Datenblobs.
 */
export async function unlockVault<T>(passphrase: string): Promise<UnlockResult<T>> {
  const file = readFile();
  if (!file) return { ok: false, reason: 'missing' };

  if (file.duress) {
    const dHash = await deriveKey(passphrase, b64.dec(file.duress.salt));
    if (constEq(dHash, b64.dec(file.duress.hash))) {
      return { ok: true, duress: true }; // Fake-Ansicht, echter Vault bleibt zu
    }
  }

  const kek = await deriveKey(passphrase, b64.dec(file.kdfSalt));
  let mk: Uint8Array;
  try {
    mk = await aesGcmDecrypt(kek, b64.dec(file.wrap));
  } catch {
    return { ok: false, reason: 'wrong-pass' }; // GCM-Tag ungültig
  }

  // Integritätsprüfung VOR dem Entschlüsseln der Daten
  const ct = b64.dec(file.data);
  const expected = hmacSha256(macKeyOf(mk), ct);
  if (!constEq(expected, b64.dec(file.mac))) {
    return { ok: false, reason: 'tampered' };
  }

  try {
    const plain = await aesGcmDecrypt(mk, ct);
    masterKey = mk;
    return { ok: true, duress: false, data: JSON.parse(utf8.dec(plain)) as T };
  } catch {
    return { ok: false, reason: 'tampered' };
  }
}

/** Integrität des gespeicherten Blobs prüfen (bei entsperrtem Vault). */
export function checkIntegrity(): 'ok' | 'tampered' | 'missing' | 'locked' {
  const file = readFile();
  if (!file) return 'missing';
  if (!masterKey) return 'locked';
  const expected = hmacSha256(macKeyOf(masterKey), b64.dec(file.data));
  return constEq(expected, b64.dec(file.mac)) ? 'ok' : 'tampered';
}

/**
 * NUR FÜR DIE DEMO: simuliert einen Angreifer, der die lokale Datenbank-
 * Datei manipuliert (Byte im Ciphertext kippen). Die nächste
 * Integritätsprüfung schlägt fehl und löst den Alarm aus.
 */
export function demoTamperVault(): void {
  const file = readFile();
  if (!file) return;
  const bytes = b64.dec(file.data);
  bytes[Math.floor(bytes.length / 2)] ^= 0xff;
  file.data = b64.enc(bytes);
  localStorage.setItem(LS_KEY, JSON.stringify(file));
}

/** Vault vollständig entfernen (Onboarding-Reset). */
export function destroyVault(): void {
  masterKey = null;
  localStorage.removeItem(LS_KEY);
}
