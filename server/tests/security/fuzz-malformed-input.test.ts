import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { WebSocket } from 'ws';
import fc from 'fast-check';
import { ed25519 } from '@noble/curves/ed25519';
import { server } from '../../src/index.js';

function b64enc(u: Uint8Array): string { return Buffer.from(u).toString('base64'); }

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

async function authedSocket(): Promise<WebSocket> {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const ws = await connect();
  const userId = `user-${Math.random().toString(36).slice(2)}`;
  await new Promise<void>((resolve) => {
    ws.once('message', (data) => {
      const m = JSON.parse(data.toString());
      if (m.type === 'challenge') {
        const sig = ed25519.sign(Buffer.from(m.nonce, 'base64'), priv);
        ws.send(JSON.stringify({ type: 'proof', sig: b64enc(sig) }));
      }
    });
    ws.once('message', () => {}); // dummy, the real wait handler is below
    const onAuthed = (data: Buffer) => {
      const m = JSON.parse(data.toString());
      if (m.type === 'authed') { ws.off('message', onAuthed); resolve(); }
    };
    ws.on('message', onAuthed);
    ws.send(JSON.stringify({
      type: 'hello', userId, deviceId: 'dev-1', deviceName: 'x',
      edPub: b64enc(pub), xPub: b64enc(pub),
    }));
  });
  return ws;
}

describe('Fuzzing — relay against arbitrary/malicious WebSocket messages', () => {
  it('raw, random bytes/strings before authentication never crash the server', async () => {
    const ws = await connect();
    await fc.assert(fc.asyncProperty(fc.string({ maxLength: 2000 }), async (raw) => {
      ws.send(raw);
      await new Promise((r) => setTimeout(r, 2));
    }), { numRuns: 100 });

    // The server must still work normally for a new, clean connection
    // afterwards — no global crash from the garbage messages.
    const fresh = await connect();
    const challenge = await new Promise<any>((resolve) => {
      fresh.once('message', (d) => resolve(JSON.parse(d.toString())));
      fresh.send(JSON.stringify({
        type: 'hello', userId: `user-${Math.random()}`, deviceId: 'd', deviceName: 'x',
        edPub: b64enc(new Uint8Array(32)), xPub: b64enc(new Uint8Array(32)),
      }));
    });
    expect(challenge.type).toBe('challenge');
    ws.close(); fresh.close();
  }, 20000);

  it('random JSON objects as authenticated messages never crash the server', async () => {
    const ws = await authedSocket();
    await fc.assert(fc.asyncProperty(fc.jsonValue(), async (value) => {
      ws.send(JSON.stringify(value));
      await new Promise((r) => setTimeout(r, 2));
    }), { numRuns: 100 });

    // The connection/server must still respond normally afterwards.
    const pingRes = await new Promise<any>((resolve) => {
      ws.once('message', (d) => resolve(JSON.parse(d.toString())));
      ws.send(JSON.stringify({ type: 'devices' }));
    });
    expect(pingRes.type === 'devices' || pingRes.type === 'error').toBe(true);
    ws.close();
  }, 20000);

  it('message types with missing/mistyped fields are rejected instead of crashing', async () => {
    const ws = await authedSocket();
    const malformed = [
      { type: 'send' },
      { type: 'send', to: 123, envelope: 'not-an-object' },
      { type: 'send', to: 'x', envelope: {} },
      { type: 'lookup' },
      { type: 'lookup', userId: null },
      { type: 'approve-device' },
      { type: 'revoke-device', deviceId: 12345 },
      { type: 'publish-otpks', keys: 'not-an-array' },
      { type: 'publish-otpks', keys: [null, undefined, 42, { id: 1 }] },
    ];
    for (const m of malformed) {
      ws.send(JSON.stringify(m));
    }
    await new Promise((r) => setTimeout(r, 100));

    const res = await new Promise<any>((resolve) => {
      ws.once('message', (d) => resolve(JSON.parse(d.toString())));
      ws.send(JSON.stringify({ type: 'devices' }));
    });
    expect(res.type).toBe('devices');
    ws.close();
  }, 10000);
});
