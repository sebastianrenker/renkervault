import { describe, it, expect, beforeEach } from 'vitest';

class MemoryStorage {
  private store = new Map<string, string>();
  getItem(key: string): string | null { return this.store.has(key) ? this.store.get(key)! : null; }
  setItem(key: string, value: string): void { this.store.set(key, value); }
  removeItem(key: string): void { this.store.delete(key); }
  clear(): void { this.store.clear(); }
}

(globalThis as unknown as { localStorage: MemoryStorage }).localStorage = new MemoryStorage();

const {
  createVault, unlockVault, saveVault, lockVault, destroyVault,
  isUnlocked, vaultExists, hasDuressPin, checkIntegrity, demoTamperVault,
} = await import('../../src/crypto/vault');

interface Data { secret: string }

beforeEach(() => {
  (globalThis as unknown as { localStorage: MemoryStorage }).localStorage.clear();
  lockVault();
});

describe('Vault — Grundfunktionen', () => {
  it('erstellt und entsperrt mit dem richtigen Passwort', async () => {
    await createVault<Data>('korrektes-passwort-123', null, { secret: 'x' });
    lockVault();
    const res = await unlockVault<Data>('korrektes-passwort-123');
    expect(res.ok).toBe(true);
    if (res.ok && !res.duress) expect(res.data.secret).toBe('x');
  });

  it('lehnt ein falsches Passwort ab', async () => {
    await createVault<Data>('richtig', null, { secret: 'x' });
    lockVault();
    const res = await unlockVault<Data>('falsch');
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('wrong-pass');
  });

  it('meldet einen fehlenden Vault korrekt', async () => {
    const res = await unlockVault('irgendwas');
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('missing');
  });

  it('vaultExists/isUnlocked spiegeln den tatsaechlichen Zustand wider', async () => {
    expect(vaultExists()).toBe(false);
    expect(isUnlocked()).toBe(false);
    await createVault<Data>('pw', null, { secret: 'x' });
    expect(vaultExists()).toBe(true);
    expect(isUnlocked()).toBe(true);
    lockVault();
    expect(isUnlocked()).toBe(false);
  });
});

describe('Vault — Duress-PIN', () => {
  it('mit konfiguriertem Duress-PIN liefert der Duress-PIN duress:true ohne Daten preiszugeben', async () => {
    await createVault<Data>('echtes-passwort', '1234', { secret: 'geheim' });
    lockVault();
    expect(hasDuressPin()).toBe(true);

    const duressRes = await unlockVault<Data>('1234');
    expect(duressRes.ok).toBe(true);
    if (duressRes.ok) expect(duressRes.duress).toBe(true);
    // Im Duress-Fall duerfen keine echten Daten im Ergebnis stehen.
    expect((duressRes as any).data).toBeUndefined();

    const realRes = await unlockVault<Data>('echtes-passwort');
    expect(realRes.ok).toBe(true);
    if (realRes.ok && !realRes.duress) expect(realRes.data.secret).toBe('geheim');
  });

  it('ein falsches Passwort wird nicht faelschlich als Duress erkannt', async () => {
    await createVault<Data>('echtes-passwort', '1234', { secret: 'geheim' });
    lockVault();
    const res = await unlockVault<Data>('irgendwas-anderes');
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('wrong-pass');
  });
});

describe('Vault — Integritaet / Tamper-Erkennung', () => {
  it('erkennt eine manipulierte Vault-Datei beim Entsperren', async () => {
    await createVault<Data>('pw', null, { secret: 'x' });
    lockVault();
    demoTamperVault();
    const res = await unlockVault<Data>('pw');
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('tampered');
  });

  it('checkIntegrity erkennt Manipulation im laufenden (entsperrten) Zustand', async () => {
    await createVault<Data>('pw', null, { secret: 'x' });
    expect(checkIntegrity()).toBe('ok');
    demoTamperVault();
    expect(checkIntegrity()).toBe('tampered');
  });

  it('saveVault aktualisiert MAC/Daten konsistent, sodass danach wieder ok ist', async () => {
    await createVault<Data>('pw', null, { secret: 'alt' });
    await saveVault<Data>({ secret: 'neu' });
    expect(checkIntegrity()).toBe('ok');
    lockVault();
    const res = await unlockVault<Data>('pw');
    if (res.ok && !res.duress) expect(res.data.secret).toBe('neu');
  });
});

describe('Vault — Sperren / Zerstoeren', () => {
  it('lockVault entfernt den Zugriff auf den Master-Key', async () => {
    await createVault<Data>('pw', null, { secret: 'x' });
    expect(isUnlocked()).toBe(true);
    lockVault();
    expect(isUnlocked()).toBe(false);
  });

  it('destroyVault entfernt die Vault-Datei vollstaendig', async () => {
    await createVault<Data>('pw', null, { secret: 'x' });
    destroyVault();
    expect(vaultExists()).toBe(false);
    expect(isUnlocked()).toBe(false);
    const res = await unlockVault('pw');
    expect(res.ok).toBe(false);
  });
});
