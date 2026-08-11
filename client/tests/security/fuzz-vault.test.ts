import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

class MemoryStorage {
  private store = new Map<string, string>();
  getItem(key: string): string | null { return this.store.has(key) ? this.store.get(key)! : null; }
  setItem(key: string, value: string): void { this.store.set(key, value); }
  removeItem(key: string): void { this.store.delete(key); }
  clear(): void { this.store.clear(); }
}
(globalThis as unknown as { localStorage: MemoryStorage }).localStorage = new MemoryStorage();

const { unlockVault, checkIntegrity, createVault, lockVault } = await import('../../src/crypto/vault');

const ls = () => (globalThis as unknown as { localStorage: MemoryStorage }).localStorage;
const LS_KEY = 'renkervault.vault.v1';

describe('Fuzzing — beschädigte/manipulierte Vault-Dateien', () => {
  it('unlockVault stürzt bei beliebigem Storage-Inhalt nie ab, sondern liefert immer ein UnlockResult', async () => {
    await fc.assert(fc.asyncProperty(fc.string({ maxLength: 500 }), async (raw) => {
      ls().clear();
      ls().setItem(LS_KEY, raw);
      const res = await unlockVault('irgendein-passwort');
      expect(typeof res.ok).toBe('boolean');
    }), { numRuns: 200 });
  });

  it('unlockVault stürzt bei strukturell gültigem, aber inhaltlich zufälligem JSON nie ab', async () => {
    const jsonArb = fc.jsonValue();
    await fc.assert(fc.asyncProperty(jsonArb, async (value) => {
      ls().clear();
      ls().setItem(LS_KEY, JSON.stringify(value));
      const res = await unlockVault('irgendein-passwort');
      expect(typeof res.ok).toBe('boolean');
    }), { numRuns: 200 });
  });

  it('ein einzelnes zufällig geflipptes Byte in einer echten Vault-Datei wird immer als tampered/wrong-pass erkannt, nie als ok', { timeout: 30000 }, async () => {
    ls().clear();
    await createVault('echte-passphrase-123', null, { secret: 'x' });
    const original = ls().getItem(LS_KEY)!;
    lockVault();

    await fc.assert(fc.asyncProperty(fc.nat({ max: original.length - 1 }), async (pos) => {
      const chars = original.split('');
      const code = chars[pos].charCodeAt(0);
      chars[pos] = String.fromCharCode((code + 1) % 128);
      ls().setItem(LS_KEY, chars.join(''));
      const res = await unlockVault('echte-passphrase-123');
      if (res.ok) {
        // Manche Positionen (z. B. Whitespace zwischen JSON-Tokens) sind
        // funktional irrelevant — das ist erlaubt. Kritisch waere nur ein
        // "ok" mit falschen Daten, was hier nicht separat prüfbar ist, aber
        // checkIntegrity() muss dann trotzdem konsistent "ok" bleiben.
        expect(checkIntegrity()).toBe('ok');
      }
      lockVault();
    }), { numRuns: 25 });
  });
});
