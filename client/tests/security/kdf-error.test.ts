import { describe, it, expect, vi } from 'vitest';

vi.mock('hash-wasm', () => ({
  argon2id: vi.fn(async () => { throw new Error('simulated WASM OOM'); }),
}));

class MemoryStorage {
  private store = new Map<string, string>();
  getItem(key: string): string | null { return this.store.has(key) ? this.store.get(key)! : null; }
  setItem(key: string, value: string): void { this.store.set(key, value); }
  removeItem(key: string): void { this.store.delete(key); }
  clear(): void { this.store.clear(); }
}
(globalThis as unknown as { localStorage: MemoryStorage }).localStorage = new MemoryStorage();

describe('an Argon2id execution error is distinguished from "wrong password" (ARGON2-ERR)', () => {
  it('deriveKey throws a KdfExecutionError, not a generic password problem', async () => {
    const { deriveKey, KdfExecutionError } = await import('../../src/crypto/primitives');
    await expect(deriveKey('some-password', new Uint8Array(16))).rejects.toBeInstanceOf(KdfExecutionError);
  });

  it('unlockVault reports reason "kdf-error" instead of "wrong-pass" when Argon2id fails', async () => {
    const { unlockVault } = await import('../../src/crypto/vault');
    // It is enough that a vault file exists at all — the KDF already fails
    // before any MAC/password check.
    (globalThis as unknown as { localStorage: MemoryStorage }).localStorage.setItem(
      'renkervault.vault.v1',
      JSON.stringify({
        v: 1, createdAt: Date.now(), kdfSalt: 'AAAAAAAAAAAAAAAAAAAAAA==',
        wrap: 'AAAA', duress: null, generation: 1, data: 'AAAA', mac: 'AAAA',
      })
    );

    const res = await unlockVault('some-password');
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('kdf-error');
  });
});
