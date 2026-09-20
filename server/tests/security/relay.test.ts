import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { WebSocket } from 'ws';
import { ed25519 } from '@noble/curves/ed25519';
import { server, users, sweep, QUEUE_TTL_MS } from '../../src/index.js';

function b64enc(u: Uint8Array): string { return Buffer.from(u).toString('base64'); }
function b64dec(s: string): Uint8Array { return new Uint8Array(Buffer.from(s, 'base64')); }

function newIdentity() {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  return { priv, pub };
}

function uid(): string { return Math.random().toString(36).slice(2); }

let port: number;

beforeAll(async () => {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('no port');
  port = addr.port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}, 15000);

function connect(): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
  });
}

function onceMsg(ws: WebSocket, predicate?: (m: any) => boolean, timeoutMs = 2000): Promise<any> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { ws.off('message', handler); reject(new Error('timeout waiting for message')); }, timeoutMs);
    const handler = (data: any) => {
      const m = JSON.parse(data.toString());
      if (!predicate || predicate(m)) { clearTimeout(timer); ws.off('message', handler); resolve(m); }
    };
    ws.on('message', handler);
  });
}

function noMsg(ws: WebSocket, predicate: (m: any) => boolean, waitMs = 400): Promise<boolean> {
  return new Promise((resolve) => {
    const handler = (data: any) => {
      const m = JSON.parse(data.toString());
      if (predicate(m)) { clearTimeout(timer); ws.off('message', handler); resolve(false); }
    };
    ws.on('message', handler);
    const timer = setTimeout(() => { ws.off('message', handler); resolve(true); }, waitMs);
  });
}

async function registerDevice(userId: string, deviceId: string, deviceName: string) {
  const id = newIdentity();
  const ws = await connect();
  ws.send(JSON.stringify({
    type: 'hello', userId, deviceId, deviceName,
    edPub: b64enc(id.pub), xPub: b64enc(id.pub), prekeyPub: b64enc(id.pub), pqPrekeyPub: b64enc(id.pub),
    prekeySig: b64enc(ed25519.sign(id.pub, id.priv)), pqPrekeySig: b64enc(ed25519.sign(id.pub, id.priv)),
  }));
  const challenge = await onceMsg(ws, (m) => m.type === 'challenge');
  const sig = ed25519.sign(b64dec(challenge.nonce), id.priv);
  ws.send(JSON.stringify({ type: 'proof', sig: b64enc(sig) }));
  const result = await onceMsg(ws, (m) => m.type === 'authed' || m.type === 'auth-failed' || m.type === 'locked');
  return { ws, id, result };
}

describe('Relay — auth and challenge-response flow', () => {
  it('the first device of an account becomes trusted automatically (bootstrap TOFU)', async () => {
    const { ws, result } = await registerDevice(`user-${uid()}`, 'dev-1', 'Phone');
    expect(result.type).toBe('authed');
    expect(result.trusted).toBe(true);
    ws.close();
  });

  it('a wrong signature is rejected', async () => {
    const userId = `user-${uid()}`;
    const id = newIdentity();
    const ws = await connect();
    ws.send(JSON.stringify({
      type: 'hello', userId, deviceId: 'dev-1', deviceName: 'x',
      edPub: b64enc(id.pub), xPub: b64enc(id.pub),
    }));
    await onceMsg(ws, (m) => m.type === 'challenge');
    ws.send(JSON.stringify({ type: 'proof', sig: b64enc(new Uint8Array(64)) }));
    const result = await onceMsg(ws, (m) => m.type === 'auth-failed');
    expect(result.type).toBe('auth-failed');
    ws.close();
  });

  it('five failed attempts lead to a lockout', async () => {
    const userId = `user-${uid()}`;
    const id = newIdentity(); // the same registered identity, but wrong signatures
    for (let i = 0; i < 5; i++) {
      const ws = await connect();
      ws.send(JSON.stringify({
        type: 'hello', userId, deviceId: 'dev-fail', deviceName: 'x',
        edPub: b64enc(id.pub), xPub: b64enc(id.pub),
      }));
      await onceMsg(ws, (m) => m.type === 'challenge');
      ws.send(JSON.stringify({ type: 'proof', sig: b64enc(new Uint8Array(64)) }));
      await onceMsg(ws, (m) => m.type === 'auth-failed');
      ws.close();
    }
    const ws = await connect();
    ws.send(JSON.stringify({
      type: 'hello', userId, deviceId: 'dev-fail', deviceName: 'x',
      edPub: b64enc(id.pub), xPub: b64enc(id.pub),
    }));
    const result = await onceMsg(ws, (m) => m.type === 'locked');
    expect(result.type).toBe('locked');
    ws.close();
  });

  it('malformed messages do not crash the connection', async () => {
    const ws = await connect();
    ws.send('this is not JSON {{{');
    ws.send(JSON.stringify({ type: 'send', to: 123, envelope: null }));
    ws.send(JSON.stringify({}));
    // the connection must still work normally afterwards.
    const { ws: ws2, result } = await registerDevice(`user-${uid()}`, 'dev-1', 'x');
    expect(result.type).toBe('authed');
    ws.close();
    ws2.close();
  });
});

describe('Relay — multi-device trust model (P0 regression tests)', () => {
  it('a second, unconfirmed device is not trusted automatically', async () => {
    const userId = `user-${uid()}`;
    const { ws: ws1 } = await registerDevice(userId, 'dev-1', 'First device');
    const { ws: ws2, result: r2 } = await registerDevice(userId, 'dev-2', 'Second device');
    expect(r2.trusted).toBe(false);
    ws1.close(); ws2.close();
  });

  it('an unconfirmed device can NOT approve itself', async () => {
    const userId = `user-${uid()}`;
    const { ws: ws1 } = await registerDevice(userId, 'dev-1', 'First device');
    const { ws: ws2 } = await registerDevice(userId, 'dev-2', 'Attacker device');

    ws2.send(JSON.stringify({ type: 'approve-device', deviceId: 'dev-2' }));
    const err = await onceMsg(ws2, (m) => m.type === 'error');
    expect(err.error).toBe('not-trusted');

    ws1.send(JSON.stringify({ type: 'devices' }));
    const list = await onceMsg(ws1, (m) => m.type === 'devices');
    const dev2 = list.devices.find((d: any) => d.deviceId === 'dev-2');
    expect(dev2.trusted).toBe(false);
    ws1.close(); ws2.close();
  });

  it('an unconfirmed device can NOT sign out the real device (account-takeover protection)', async () => {
    const userId = `user-${uid()}`;
    const { ws: ws1 } = await registerDevice(userId, 'dev-1', 'First device');
    const { ws: ws2 } = await registerDevice(userId, 'dev-2', 'Attacker device');

    ws2.send(JSON.stringify({ type: 'revoke-device', deviceId: 'dev-1' }));
    const err = await onceMsg(ws2, (m) => m.type === 'error');
    expect(err.error).toBe('not-trusted');

    ws1.send(JSON.stringify({ type: 'devices' }));
    const list = await onceMsg(ws1, (m) => m.type === 'devices');
    expect(list.devices.some((d: any) => d.deviceId === 'dev-1')).toBe(true);
    ws1.close(); ws2.close();
  });

  it('a confirmed device can correctly approve a new device', async () => {
    const userId = `user-${uid()}`;
    const { ws: ws1 } = await registerDevice(userId, 'dev-1', 'First device');
    const { ws: ws2 } = await registerDevice(userId, 'dev-2', 'Second device (real)');

    ws1.send(JSON.stringify({ type: 'approve-device', deviceId: 'dev-2' }));
    await onceMsg(ws2, (m) => m.type === 'security-event' && m.kind === 'device-approved');

    ws2.send(JSON.stringify({ type: 'devices' }));
    const list = await onceMsg(ws2, (m) => m.type === 'devices');
    expect(list.devices.find((d: any) => d.deviceId === 'dev-2').trusted).toBe(true);
    ws1.close(); ws2.close();
  });

  it('live-delivered messages reach only trusted devices', async () => {
    const userId = `user-${uid()}`;
    const { ws: ws1 } = await registerDevice(userId, 'dev-1', 'First device');
    const { ws: ws2 } = await registerDevice(userId, 'dev-2', 'Unconfirmed device');
    ws1.close(); // only the unconfirmed device stays online

    const { ws: sender } = await registerDevice(`user-${uid()}`, 'dev-s', 'Sender');
    sender.send(JSON.stringify({ type: 'send', to: userId, envelope: { ct: 'secret', chatId: 'c', chatKind: 'direct', kind: 'text', msgId: 'm1', ts: Date.now(), fromName: 'x' } }));

    const noneDelivered = await noMsg(ws2, (m) => m.type === 'deliver');
    expect(noneDelivered).toBe(true);
    ws2.close(); sender.close();
  });

  it('lookup returns exclusively the key bundle of the trusted device', async () => {
    const userId = `user-${uid()}`;
    const { ws: ws1, id: id1 } = await registerDevice(userId, 'dev-1', 'Real device');
    const { ws: ws2 } = await registerDevice(userId, 'dev-2', 'Unconfirmed device');

    const { ws: requester } = await registerDevice(`user-${uid()}`, 'dev-r', 'Requesting device');
    requester.send(JSON.stringify({ type: 'lookup', userId, ref: 'r1' }));
    const res = await onceMsg(requester, (m) => m.type === 'lookup-result');
    expect(res.edPub).toBe(b64enc(id1.pub));

    ws1.close(); ws2.close(); requester.close();
  });

  it('lookup passes on the prekey signatures stored by the device unchanged (PREKEY-SIG transport)', async () => {
    const userId = `user-${uid()}`;
    const { ws: ws1 } = await registerDevice(userId, 'dev-1', 'Real device');
    const { ws: requester } = await registerDevice(`user-${uid()}`, 'dev-r', 'Requesting device');

    requester.send(JSON.stringify({ type: 'lookup', userId, ref: 'r2' }));
    const res = await onceMsg(requester, (m) => m.type === 'lookup-result');
    expect(typeof res.prekeySig).toBe('string');
    expect(typeof res.pqPrekeySig).toBe('string');

    ws1.close(); requester.close();
  });
});

describe('Relay — bounded storage (phantom accounts / queue TTL)', () => {
  it('sweep() removes device-less phantom accounts with an empty, expired queue', () => {
    const staleId = `phantom-${uid()}`;
    users.set(staleId, { devices: new Map(), queue: [], createdAt: Date.now() - QUEUE_TTL_MS - 1000 });
    const freshId = `phantom-${uid()}`;
    users.set(freshId, { devices: new Map(), queue: [], createdAt: Date.now() });

    sweep();

    expect(users.has(staleId)).toBe(false);
    expect(users.has(freshId)).toBe(true);
    users.delete(freshId);
  });

  it('sweep() removes expired but not fresh queue entries', () => {
    const id = `queued-${uid()}`;
    users.set(id, {
      devices: new Map(),
      queue: [
        { type: 'deliver', ts: Date.now() - QUEUE_TTL_MS - 1000 },
        { type: 'deliver', ts: Date.now() },
      ],
      createdAt: Date.now() - QUEUE_TTL_MS - 1000,
    });

    sweep();

    const u = users.get(id);
    expect(u).toBeDefined();
    expect(u!.queue.length).toBe(1);
    users.delete(id);
  });
});

describe('Relay — user-enumeration protection (RELAY-ENUM)', () => {
  it('also limits normal (non-handshake) lookups per account', async () => {
    const { ws } = await registerDevice(`user-${uid()}`, 'dev-1', 'x');
    const target = `user-${uid()}`;

    let rateLimitError: string | null = null;
    for (let i = 0; i < 65; i++) {
      ws.send(JSON.stringify({ type: 'lookup', userId: target, ref: `r${i}` }));
      const res = await onceMsg(ws, (m) => m.type === 'lookup-result' || m.type === 'error');
      if (res.type === 'error') { rateLimitError = res.error; break; }
      // Stays under the generic per-socket message limit (30/s), so that
      // the lookup-specific limit (60/5min) is tested specifically.
      await new Promise((r) => setTimeout(r, 40));
    }

    expect(rateLimitError).toBe('lookup-rate-limited');
    ws.close();
  }, 10000);
});
