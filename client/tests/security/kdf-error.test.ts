import { describe, it, expect, vi } from 'vitest';

vi.mock('hash-wasm', () => ({
  argon2id: vi.fn(async () => { throw new Error('simulierter WASM-OOM'); }),
}));

class MemoryStorage {
  private store = new Map<string, string>();
  getItem(key: string): string | null { return this.store.has(key) ? this.store.get(key)! : null; }
  setItem(key: string, value: string): void { this.store.set(key, value); }
  removeItem(key: string): void { this.store.delete(key); }
  clear(): void { this.store.clear(); }
}
(globalThis as unknown as { localStorage: MemoryStorage }).localStorage = new MemoryStorage();

describe('Argon2id-Ausführungsfehler wird von "falsches Passwort" unterschieden (ARGON2-ERR)', () => {
  it('deriveKey wirft eine KdfExecutionError, kein generisches Passwort-Problem', async () => {
    const { deriveKey, KdfExecutionError } = await import('../../src/crypto/primitives');
    await expect(deriveKey('irgendein-passwort', new Uint8Array(16))).rejects.toBeInstanceOf(KdfExecutionError);
  });

  it('unlockVault meldet reason "kdf-error" statt "wrong-pass", wenn Argon2id fehlschlägt', async () => {
    const { unlockVault } = await import('../../src/crypto/vault');
    // Es reicht, dass überhaupt eine Vault-Datei existiert — die KDF schlägt
    // bereits vor jeder MAC-/Passwort-Prüfung fehl.
    (globalThis as unknown as { localStorage: MemoryStorage }).localStorage.setItem(
      'renkervault.vault.v1',
      JSON.stringify({
        v: 1, createdAt: Date.now(), kdfSalt: 'AAAAAAAAAAAAAAAAAAAAAA==',
        wrap: 'AAAA', duress: null, generation: 1, data: 'AAAA', mac: 'AAAA',
      })
    );

    const res = await unlockVault('irgendein-passwort');
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('kdf-error');
  });
});
