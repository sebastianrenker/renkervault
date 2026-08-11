import { describe, it, expect } from 'vitest';
import { b64 } from '../../src/crypto/primitives';
import { RealChatEngine } from '../../src/net/realchat';
import { newGroupEpochKey } from '../../src/crypto/ratchet';

describe('Gruppen-Verschlüsselung — Epoch-Rollback-Schutz (GROUP-A)', () => {
  it('nimmt eine group-key-Nachricht mit steigender Epoche an', () => {
    const engine = new RealChatEngine();
    const chatId = 'grp-1';
    const key1 = b64.enc(newGroupEpochKey());
    const key2 = b64.enc(newGroupEpochKey());

    expect(engine.applyGroupKey(chatId, key1, 1)).not.toBeNull();
    expect(engine.applyGroupKey(chatId, key2, 2)).not.toBeNull();
    expect(engine.currentGroupKeyB64(chatId)?.epoch).toBe(2);
    expect(engine.currentGroupKeyB64(chatId)?.key).toBe(key2);
  });

  it('lehnt eine replayte, veraltete group-key-Nachricht ab (Epoch-Rollback)', () => {
    const engine = new RealChatEngine();
    const chatId = 'grp-2';
    const oldKey = b64.enc(newGroupEpochKey());
    const newKey = b64.enc(newGroupEpochKey());

    engine.applyGroupKey(chatId, oldKey, 1);
    engine.applyGroupKey(chatId, newKey, 2);

    // Angreifer/böswilliges Mitglied dupliziert die ALTE group-key-Nachricht (Epoche 1)
    const result = engine.applyGroupKey(chatId, oldKey, 1);

    expect(result).toBeNull();
    // Der aktuelle (neuere) Schlüssel darf dadurch nicht verdrängt worden sein.
    expect(engine.currentGroupKeyB64(chatId)?.epoch).toBe(2);
    expect(engine.currentGroupKeyB64(chatId)?.key).toBe(newKey);
  });

  it('lehnt eine erneute Zustellung derselben Epoche ab (kein stiller Downgrade auf denselben Stand)', () => {
    const engine = new RealChatEngine();
    const chatId = 'grp-3';
    const key = b64.enc(newGroupEpochKey());

    engine.applyGroupKey(chatId, key, 5);
    const replay = engine.applyGroupKey(chatId, key, 5);

    expect(replay).toBeNull();
  });

  it('akzeptiert den allerersten Schlüssel für eine neue Gruppe unabhängig von der Startepoche', () => {
    const engine = new RealChatEngine();
    const chatId = 'grp-4';
    const key = b64.enc(newGroupEpochKey());

    expect(engine.applyGroupKey(chatId, key, 1)).not.toBeNull();
  });

  it('ein kompromittierter alter Epoch-Key bleibt nach Rotation nutzlos, solange kein Replay erfolgreich ist', async () => {
    const engine = new RealChatEngine();
    const chatId = 'grp-5';
    const oldKey = b64.enc(newGroupEpochKey());
    const newKey = b64.enc(newGroupEpochKey());

    engine.applyGroupKey(chatId, oldKey, 1);
    const enc = await engine.encryptGroup(chatId, new TextEncoder().encode('vor der rotation'));
    expect(enc.epoch).toBe(1);

    engine.applyGroupKey(chatId, newKey, 2);
    // Rollback-Versuch auf den alten (kompromittiert angenommenen) Schlüssel schlägt fehl.
    expect(engine.applyGroupKey(chatId, oldKey, 1)).toBeNull();

    const enc2 = await engine.encryptGroup(chatId, new TextEncoder().encode('nach der rotation'));
    expect(enc2.epoch).toBe(2);
  });
});
