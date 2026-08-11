import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { WebSocket } from 'ws';

process.env.ALLOWED_ORIGINS = 'https://chat.example.com';
const { server } = await import('../../src/index.js');

let port: number;

beforeAll(async () => {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('kein Port');
  port = addr.port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}, 15000);

function connectWithOrigin(origin: string | undefined): Promise<{ ok: boolean; code?: number }> {
  return new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`, origin ? { origin } : undefined);
    ws.once('open', () => { resolve({ ok: true }); ws.close(); });
    ws.once('unexpected-response', (_req, res) => { resolve({ ok: false, code: res.statusCode }); });
    ws.once('error', () => resolve({ ok: false }));
  });
}

describe('Relay — Origin-Validierung (RELAY-ORIGIN)', () => {
  it('lehnt eine Verbindung mit nicht erlaubtem Origin ab', async () => {
    const res = await connectWithOrigin('https://boesartige-seite.example');
    expect(res.ok).toBe(false);
    expect(res.code).toBe(403);
  });

  it('lässt eine Verbindung mit erlaubtem Origin zu', async () => {
    const res = await connectWithOrigin('https://chat.example.com');
    expect(res.ok).toBe(true);
  });

  it('lässt Verbindungen ohne Origin-Header zu (native Clients wie Tauri/Android)', async () => {
    const res = await connectWithOrigin(undefined);
    expect(res.ok).toBe(true);
  });
});
