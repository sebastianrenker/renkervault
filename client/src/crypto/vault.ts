import { invoke, isTauri } from '@tauri-apps/api/core';
import {
  rand, b64, utf8, deriveKey, constEq,
  aesGcmEncrypt, aesGcmDecrypt, hkdfSha256, hmacSha256,
} from './primitives';

const LS_KEY = 'renkervault.vault.v1';

interface VaultFile {
  v: 1;
  createdAt: number;
  kdfSalt: string;
  wrap: string;
  dpapiWrapped?: boolean;
  duress: { salt: string; hash: string } | null;
  data: string;
  mac: string;
}

export type UnlockResult<T> =
  | { ok: true; duress: false; data: T }
  | { ok: true; duress: true }
  | { ok: false; reason: 'wrong-pass' | 'tampered' | 'missing' | 'device-mismatch' };

async function dpapiAvailable(): Promise<boolean> {
  if (!isTauri()) return false;
  try { return await invoke<boolean>('dpapi_available'); } catch { return false; }
}

async function dpapiWrap(bytes: Uint8Array): Promise<Uint8Array> {
  const out = await invoke<number[]>('dpapi_protect', { data: Array.from(bytes) });
  return new Uint8Array(out);
}

async function dpapiUnwrap(bytes: Uint8Array): Promise<Uint8Array> {
  const out = await invoke<number[]>('dpapi_unprotect', { data: Array.from(bytes) });
  return new Uint8Array(out);
}

let masterKey: Uint8Array | null = null;

// Ueberschreibt den in JS sichtbaren Puffer vor dem Dereferenzieren. Kein Garant
// gegen forensische Wiederherstellung (V8/WebCrypto koennen intern eigene Kopien
// halten, die von JS aus nicht erreichbar sind), aber entfernt zuverlaessig die
// laenglebigste, direkt referenzierte Kopie des Master-Keys aus dem Heap.
function zero(u: Uint8Array | null): void {
  if (u) u.fill(0);
}

function macKeyOf(mk: Uint8Array): Uint8Array {
  return hkdfSha256(mk, new Uint8Array(32), 'RenkerVault-Vault-MAC', 32);
}

function readFile(): VaultFile | null {
  const raw = localStorage.getItem(LS_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw) as VaultFile; } catch { return null; }
}

// Bestmoegliches Ueberschreiben vor dem Loeschen. Kein Garant gegen forensische
// Wiederherstellung auf Storage-Engine-Ebene (LevelDB/SQLite-Backing von Browser
// bzw. WebView kann durch Compaction weiterhin alte Kopien enthalten), aber
// entfernt den unmittelbar ueber die localStorage-API sichtbaren Klartext-Slot.
function secureRemove(key: string): void {
  for (let i = 0; i < 3; i++) localStorage.setItem(key, b64.enc(rand(4096)));
  localStorage.removeItem(key);
}

export function vaultExists(): boolean { return readFile() !== null; }
export function hasDuressPin(): boolean { return readFile()?.duress != null; }
export function isUnlocked(): boolean { return masterKey !== null; }
export function lockVault(): void { zero(masterKey); masterKey = null; }

export async function createVault<T>(
  passphrase: string, duressPin: string | null, data: T
): Promise<void> {
  const kdfSalt = rand(16);
  const kek = await deriveKey(passphrase, kdfSalt);
  const mk = rand(32);
  let wrap = await aesGcmEncrypt(kek, mk);

  const dpapiOn = await dpapiAvailable();
  if (dpapiOn) wrap = await dpapiWrap(wrap);

  let duress: VaultFile['duress'] = null;
  if (duressPin) {
    const dSalt = rand(16);
    duress = { salt: b64.enc(dSalt), hash: b64.enc(await deriveKey(duressPin, dSalt)) };
  }

  masterKey = mk;
  const { data: ct, mac } = await sealData(data);
  const file: VaultFile = {
    v: 1, createdAt: Date.now(),
    kdfSalt: b64.enc(kdfSalt), wrap: b64.enc(wrap), dpapiWrapped: dpapiOn,
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

export async function saveVault<T>(data: T): Promise<void> {
  const file = readFile();
  if (!file || !masterKey) return;
  const sealed = await sealData(data);
  file.data = sealed.data;
  file.mac = sealed.mac;
  localStorage.setItem(LS_KEY, JSON.stringify(file));
}

export async function unlockVault<T>(passphrase: string): Promise<UnlockResult<T>> {
  const file = readFile();
  if (!file) return { ok: false, reason: 'missing' };

  const duressSalt = file.duress ? b64.dec(file.duress.salt) : b64.dec(file.kdfSalt);
  const [dHash, kek] = await Promise.all([
    deriveKey(passphrase, duressSalt),
    deriveKey(passphrase, b64.dec(file.kdfSalt)),
  ]);

  if (file.duress && constEq(dHash, b64.dec(file.duress.hash))) {
    return { ok: true, duress: true };
  }

  let wrapBytes = b64.dec(file.wrap);
  if (file.dpapiWrapped) {
    try {
      wrapBytes = await dpapiUnwrap(wrapBytes);
    } catch {
      return { ok: false, reason: 'device-mismatch' };
    }
  }

  let mk: Uint8Array;
  try {
    mk = await aesGcmDecrypt(kek, wrapBytes);
  } catch {
    return { ok: false, reason: 'wrong-pass' };
  }

  const ct = b64.dec(file.data);
  const expected = hmacSha256(macKeyOf(mk), ct);
  if (!constEq(expected, b64.dec(file.mac))) {
    zero(mk);
    return { ok: false, reason: 'tampered' };
  }

  try {
    const plain = await aesGcmDecrypt(mk, ct);
    masterKey = mk;
    return { ok: true, duress: false, data: JSON.parse(utf8.dec(plain)) as T };
  } catch {
    zero(mk);
    return { ok: false, reason: 'tampered' };
  }
}

export function checkIntegrity(): 'ok' | 'tampered' | 'missing' | 'locked' {
  const file = readFile();
  if (!file) return 'missing';
  if (!masterKey) return 'locked';
  const expected = hmacSha256(macKeyOf(masterKey), b64.dec(file.data));
  return constEq(expected, b64.dec(file.mac)) ? 'ok' : 'tampered';
}

export function demoTamperVault(): void {
  const file = readFile();
  if (!file) return;
  const bytes = b64.dec(file.data);
  bytes[Math.floor(bytes.length / 2)] ^= 0xff;
  file.data = b64.enc(bytes);
  localStorage.setItem(LS_KEY, JSON.stringify(file));
}

export function destroyVault(): void {
  zero(masterKey);
  masterKey = null;
  secureRemove(LS_KEY);
}
