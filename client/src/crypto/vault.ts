import { invoke, isTauri } from '@tauri-apps/api/core';
import {
  rand, b64, utf8, deriveKey, constEq, concat, KdfExecutionError,
  aesGcmEncrypt, aesGcmDecrypt, hkdfSha256, hmacSha256,
} from './primitives';

const LS_KEY = 'renkervault.vault.v1';
// Separater Schlüssel: haelt die hoechste je gesehene Generation fest, um ein
// unbemerktes Zurueckspielen einer aelteren, aber weiterhin gueltig
// signierten Vault-Version zu erkennen (Rollback-Schutz, siehe
// SECURITY_AUDIT.md STORAGE-ROLLBACK). Schuetzt gezielt gegen das
// Wiedereinspielen eines aelteren, isoliert exfiltrierten Vault-Snapshots —
// nicht gegen ein Zuruecksetzen des GESAMTEN Storage-Ursprungs inkl. dieses
// Zaehlers selbst (dagegen gibt es aus einer Web-/WebView-Laufzeit heraus
// keinen technischen Schutz).
const GEN_KEY = 'renkervault.vault.gen.v1';

interface VaultFile {
  v: 1;
  createdAt: number;
  kdfSalt: string;
  wrap: string;
  dpapiWrapped?: boolean;
  duress: { salt: string; hash: string } | null;
  generation?: number;
  data: string;
  mac: string;
}

export type UnlockResult<T> =
  | { ok: true; duress: false; data: T }
  | { ok: true; duress: true }
  | { ok: false; reason: 'wrong-pass' | 'tampered' | 'missing' | 'device-mismatch' | 'kdf-error' };

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

function maxGenerationSeen(): number {
  const raw = localStorage.getItem(GEN_KEY);
  const n = raw ? Number(raw) : 0;
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function recordGenerationSeen(gen: number): void {
  localStorage.setItem(GEN_KEY, String(gen));
}

function macInput(ct: Uint8Array, generation: number): Uint8Array {
  return concat(ct, utf8.enc(String(generation)));
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
  const generation = 1;
  const { data: ct, mac } = await sealData(data, generation);
  const file: VaultFile = {
    v: 1, createdAt: Date.now(),
    kdfSalt: b64.enc(kdfSalt), wrap: b64.enc(wrap), dpapiWrapped: dpapiOn,
    duress, generation, data: ct, mac,
  };
  localStorage.setItem(LS_KEY, JSON.stringify(file));
  recordGenerationSeen(generation);
}

async function sealData<T>(data: T, generation: number): Promise<{ data: string; mac: string }> {
  if (!masterKey) throw new Error('Vault ist gesperrt');
  const ct = await aesGcmEncrypt(masterKey, utf8.enc(JSON.stringify(data)));
  const mac = hmacSha256(macKeyOf(masterKey), macInput(ct, generation));
  return { data: b64.enc(ct), mac: b64.enc(mac) };
}

export async function saveVault<T>(data: T): Promise<void> {
  const file = readFile();
  if (!file || !masterKey) return;
  const generation = (file.generation ?? 0) + 1;
  const sealed = await sealData(data, generation);
  file.generation = generation;
  file.data = sealed.data;
  file.mac = sealed.mac;
  localStorage.setItem(LS_KEY, JSON.stringify(file));
  recordGenerationSeen(generation);
}

export type ChangePassphraseResult = { ok: true } | { ok: false; reason: 'wrong-pass' | 'missing' | 'locked' };

// Wrappt denselben Master-Key mit einem neu abgeleiteten KEK unter neuem
// Salt — der Master-Key selbst (und damit alle bestehenden Ratchet-/
// Gruppensitzungen) bleibt unverändert, nur die Passphrase, die ihn schützt,
// wechselt. Verlangt bewusst die alte Passphrase, damit ein kurzzeitig
// unbeaufsichtigt entsperrtes Gerät nicht durch bloßes Setzen einer neuen
// Passphrase gekapert werden kann.
export async function changePassphrase(oldPassphrase: string, newPassphrase: string): Promise<ChangePassphraseResult> {
  if (!masterKey) return { ok: false, reason: 'locked' };
  const file = readFile();
  if (!file) return { ok: false, reason: 'missing' };

  const oldKek = await deriveKey(oldPassphrase, b64.dec(file.kdfSalt));
  let oldWrapBytes = b64.dec(file.wrap);
  if (file.dpapiWrapped) {
    try { oldWrapBytes = await dpapiUnwrap(oldWrapBytes); } catch { return { ok: false, reason: 'wrong-pass' }; }
  }
  let confirmedMk: Uint8Array;
  try { confirmedMk = await aesGcmDecrypt(oldKek, oldWrapBytes); } catch { return { ok: false, reason: 'wrong-pass' }; }
  const matches = constEq(confirmedMk, masterKey);
  zero(confirmedMk);
  if (!matches) return { ok: false, reason: 'wrong-pass' };

  const newSalt = rand(16);
  const newKek = await deriveKey(newPassphrase, newSalt);
  let newWrap = await aesGcmEncrypt(newKek, masterKey);
  const dpapiOn = await dpapiAvailable();
  if (dpapiOn) newWrap = await dpapiWrap(newWrap);

  const generation = (file.generation ?? 0) + 1;
  const ct = b64.dec(file.data);
  file.kdfSalt = b64.enc(newSalt);
  file.wrap = b64.enc(newWrap);
  file.dpapiWrapped = dpapiOn;
  file.generation = generation;
  file.mac = b64.enc(hmacSha256(macKeyOf(masterKey), macInput(ct, generation)));
  localStorage.setItem(LS_KEY, JSON.stringify(file));
  recordGenerationSeen(generation);
  return { ok: true };
}

// Öffentlicher Einstiegspunkt: fängt JEDE unerwartete Exception ab (z. B.
// ungültiges Base64 in einem manipulierten/korrupten Feld, das atob() nicht
// dekodieren kann) und behandelt sie als "tampered" statt sie ungefangen
// durchzureichen. Von Fuzzing-Tests gefunden (fuzz-vault.test.ts) — eine
// manipulierte Vault-Datei darf die App nie zum Absturz bringen.
export async function unlockVault<T>(passphrase: string): Promise<UnlockResult<T>> {
  try {
    return await unlockVaultInner<T>(passphrase);
  } catch (err) {
    if (err instanceof KdfExecutionError) return { ok: false, reason: 'kdf-error' };
    return { ok: false, reason: 'tampered' };
  }
}

async function unlockVaultInner<T>(passphrase: string): Promise<UnlockResult<T>> {
  const file = readFile();
  if (!file) return { ok: false, reason: 'missing' };

  const duressSalt = file.duress ? b64.dec(file.duress.salt) : b64.dec(file.kdfSalt);
  let dHash: Uint8Array, kek: Uint8Array;
  try {
    [dHash, kek] = await Promise.all([
      deriveKey(passphrase, duressSalt),
      deriveKey(passphrase, b64.dec(file.kdfSalt)),
    ]);
  } catch (err) {
    if (err instanceof KdfExecutionError) return { ok: false, reason: 'kdf-error' };
    throw err;
  }

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
  const mac = b64.dec(file.mac);
  // Ältere Tresordateien (vor Einführung des Generation-Counters) haben kein
  // `generation`-Feld — ihr MAC wurde ohne Generation im Input berechnet.
  // Für diese wird hier zunächst nach dem alten Schema geprüft; nach
  // erfolgreichem Entsperren wird die Datei unten transparent auf das neue
  // Format migriert (generation=1, MAC neu berechnet), ohne dass der Nutzer
  // etwas davon merkt.
  const isLegacyFormat = file.generation === undefined;
  const expected = isLegacyFormat
    ? hmacSha256(macKeyOf(mk), ct)
    : hmacSha256(macKeyOf(mk), macInput(ct, file.generation!));
  if (!constEq(expected, mac)) {
    zero(mk);
    return { ok: false, reason: 'tampered' };
  }

  if (!isLegacyFormat) {
    const seen = maxGenerationSeen();
    if (file.generation! < seen) {
      zero(mk);
      return { ok: false, reason: 'tampered' };
    }
  }

  try {
    const plain = await aesGcmDecrypt(mk, ct);
    masterKey = mk;
    const generation = isLegacyFormat ? 1 : file.generation!;
    recordGenerationSeen(generation);
    if (isLegacyFormat) {
      file.generation = generation;
      file.mac = b64.enc(hmacSha256(macKeyOf(mk), macInput(ct, generation)));
      localStorage.setItem(LS_KEY, JSON.stringify(file));
    }
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
  try {
    const ct = b64.dec(file.data);
    const expected = file.generation === undefined
      ? hmacSha256(macKeyOf(masterKey), ct)
      : hmacSha256(macKeyOf(masterKey), macInput(ct, file.generation));
    return constEq(expected, b64.dec(file.mac)) ? 'ok' : 'tampered';
  } catch {
    return 'tampered';
  }
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
  localStorage.removeItem(GEN_KEY);
}
