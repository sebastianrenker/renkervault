import { describe, it, expect } from 'vitest';
import { b64 } from '../../src/crypto/primitives';
import { RealChatEngine } from '../../src/net/realchat';
import { newGroupEpochKey } from '../../src/crypto/ratchet';

describe('Group encryption — epoch rollback protection (GROUP-A)', () => {
  it('accepts a group-key message with an increasing epoch', () => {
    const engine = new RealChatEngine();
    const chatId = 'grp-1';
    const key1 = b64.enc(newGroupEpochKey());
    const key2 = b64.enc(newGroupEpochKey());

    expect(engine.applyGroupKey(chatId, key1, 1)).not.toBeNull();
    expect(engine.applyGroupKey(chatId, key2, 2)).not.toBeNull();
    expect(engine.currentGroupKeyB64(chatId)?.epoch).toBe(2);
    expect(engine.currentGroupKeyB64(chatId)?.key).toBe(key2);
  });

  it('rejects a replayed, outdated group-key message (epoch rollback)', () => {
    const engine = new RealChatEngine();
    const chatId = 'grp-2';
    const oldKey = b64.enc(newGroupEpochKey());
    const newKey = b64.enc(newGroupEpochKey());

    engine.applyGroupKey(chatId, oldKey, 1);
    engine.applyGroupKey(chatId, newKey, 2);

    // Attacker/malicious member duplicates the OLD group-key message (epoch 1)
    const result = engine.applyGroupKey(chatId, oldKey, 1);

    expect(result).toBeNull();
    // The current (newer) key must not have been displaced by this.
    expect(engine.currentGroupKeyB64(chatId)?.epoch).toBe(2);
    expect(engine.currentGroupKeyB64(chatId)?.key).toBe(newKey);
  });

  it('rejects redelivery of the same epoch (no silent downgrade to the same state)', () => {
    const engine = new RealChatEngine();
    const chatId = 'grp-3';
    const key = b64.enc(newGroupEpochKey());

    engine.applyGroupKey(chatId, key, 5);
    const replay = engine.applyGroupKey(chatId, key, 5);

    expect(replay).toBeNull();
  });

  it('accepts the very first key for a new group regardless of the starting epoch', () => {
    const engine = new RealChatEngine();
    const chatId = 'grp-4';
    const key = b64.enc(newGroupEpochKey());

    expect(engine.applyGroupKey(chatId, key, 1)).not.toBeNull();
  });

  it('a compromised old epoch key stays useless after rotation as long as no replay succeeds', async () => {
    const engine = new RealChatEngine();
    const chatId = 'grp-5';
    const oldKey = b64.enc(newGroupEpochKey());
    const newKey = b64.enc(newGroupEpochKey());

    engine.applyGroupKey(chatId, oldKey, 1);
    const enc = await engine.encryptGroup(chatId, new TextEncoder().encode('before the rotation'));
    expect(enc.epoch).toBe(1);

    engine.applyGroupKey(chatId, newKey, 2);
    // Rollback attempt to the old (assumed compromised) key fails.
    expect(engine.applyGroupKey(chatId, oldKey, 1)).toBeNull();

    const enc2 = await engine.encryptGroup(chatId, new TextEncoder().encode('after the rotation'));
    expect(enc2.epoch).toBe(2);
  });
});
