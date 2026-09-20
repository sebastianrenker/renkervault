import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { WebSocketServer } from 'ws';
import { ed25519 } from '@noble/curves/ed25519';

const PORT = process.env.PORT ? Number(process.env.PORT) : 8787;
const HOST = process.env.HOST || '0.0.0.0';
const TLS_CERT_FILE = process.env.TLS_CERT_FILE || '';
const TLS_KEY_FILE = process.env.TLS_KEY_FILE || '';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
// A comma-separated list of allowed origins for browser clients (e.g.
// "https://chat.example.com"). Native clients (Tauri/Android) usually lack
// the Origin header entirely — they are let through regardless.
// Empty/unset = no origin check (the default behavior for local
// development, where the web client and relay deliberately run on different
// localhost ports).
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);

const users = new Map();
const authGuard = new Map();
const sockets = new Map();
const connsByIp = new Map();
const sendRateByAccount = new Map();
const otpkLookupRate = new Map();
const lookupRate = new Map();

const FAIL_WINDOW_MS = 5 * 60 * 1000;
const FAIL_LIMIT = 5;
const LOCKOUT_MS = 60 * 1000;
const MAX_QUEUE = 500;
const MAX_MSG_BYTES = 2 * 1024 * 1024;
const MAX_CONNS_PER_IP = 20;
const AUTH_TIMEOUT_MS = 15 * 1000;
const MAX_OTPK_PER_DEVICE = 100;
const MAX_OTPK_PER_PUBLISH = 50;
const SEND_RATE_WINDOW_MS = 60 * 1000;
const SEND_RATE_LIMIT = 300;
const OTPK_LOOKUP_RATE_WINDOW_MS = 5 * 60 * 1000;
const OTPK_LOOKUP_RATE_LIMIT = 20;
// Also covers pure info lookups (forHandshake=false), so that
// user enumeration ("which userId exists") cannot be accelerated arbitrarily
// via this path — more generous than the stricter
// OTPK lookup limit above, since normal lookups (refreshing contact names)
// occur more often in normal operation.
const LOOKUP_RATE_WINDOW_MS = 5 * 60 * 1000;
const LOOKUP_RATE_LIMIT = 60;
// Limits how many accounts (real + phantom accounts automatically created by
// "send" to unknown recipients) the process holds in memory in total —
// without this limit, an authenticated sender could occupy unbounded memory
// through messages to arbitrarily many invented userIds.
const MAX_TRACKED_USERS = 200_000;
// After this time, undelivered messages in the offline queue expire
// and are removed on the next sweep (bounded storage instead of eternal growth).
const QUEUE_TTL_MS = 14 * 24 * 60 * 60 * 1000;
const SWEEP_INTERVAL_MS = 10 * 60 * 1000;

const b64 = {
  dec: (s) => Uint8Array.from(Buffer.from(s, 'base64')),
};

function now() { return Date.now(); }

function checkRate(map, key, limit, windowMs) {
  const t = now();
  let hits = map.get(key);
  if (!hits) { hits = []; map.set(key, hits); }
  while (hits.length && t - hits[0] > windowMs) hits.shift();
  if (hits.length >= limit) return false;
  hits.push(t);
  return true;
}

function getUser(userId) {
  let u = users.get(userId);
  if (!u) {
    u = { devices: new Map(), queue: [], createdAt: now() };
    users.set(userId, u);
  }
  return u;
}

// Removes expired queue entries and cleans up accounts that never registered
// a real device (e.g. phantom accounts created by "send" to invented recipients)
// and whose queue is now empty.
function sweep() {
  const t = now();
  for (const [userId, u] of users) {
    if (u.queue.length) u.queue = u.queue.filter((e) => t - e.ts < QUEUE_TTL_MS);
    if (u.devices.size === 0 && u.queue.length === 0 && t - (u.createdAt ?? 0) > QUEUE_TTL_MS) {
      users.delete(userId);
    }
  }
}

function guard(userId) {
  let g = authGuard.get(userId);
  if (!g) { g = { fails: [], lockedUntil: 0 }; authGuard.set(userId, g); }
  return g;
}

function toUser(userId, msg, exceptWs = null) {
  const data = JSON.stringify(msg);
  for (const [ws, meta] of sockets) {
    if (meta.authed && meta.userId === userId && ws !== exceptWs && ws.readyState === 1) {
      ws.send(data);
    }
  }
}

// Like toUser(), but delivers only to devices the account owner has already
// confirmed as trusted. A new, not-yet-confirmed device could otherwise
// simply stay online and read every incoming message live,
// without the confirmation by another device ever being enforced.
function toTrustedUser(userId, msg, u) {
  const data = JSON.stringify(msg);
  for (const [ws, meta] of sockets) {
    if (meta.authed && meta.userId === userId && ws.readyState === 1) {
      const dev = u.devices.get(meta.deviceId);
      if (dev && dev.trusted) ws.send(data);
    }
  }
}

function hasTrustedOnlineDevice(userId, u) {
  for (const meta of sockets.values()) {
    if (meta.authed && meta.userId === userId && u.devices.get(meta.deviceId)?.trusted) return true;
  }
  return false;
}

function send(ws, msg) {
  if (ws.readyState === 1) ws.send(JSON.stringify(msg));
}

function securityEvent(userId, kind, detail) {
  toUser(userId, { type: 'security-event', kind, detail, ts: now() });
}

function recordAuthFail(userId, deviceHint) {
  const g = guard(userId);
  const t = now();
  g.fails = g.fails.filter((f) => t - f < FAIL_WINDOW_MS);
  g.fails.push(t);
  securityEvent(userId, 'auth-fail', {
    attempts: g.fails.length,
    device: deviceHint || 'unknown',
  });
  if (g.fails.length >= FAIL_LIMIT) {
    g.lockedUntil = t + LOCKOUT_MS;
    g.fails = [];
    securityEvent(userId, 'lockout', { until: g.lockedUntil, seconds: LOCKOUT_MS / 1000 });
    console.log(`[GUARD] Lockout for ${userId} (${FAIL_LIMIT} failed attempts)`);
    return true;
  }
  return false;
}

const useTls = !!(TLS_CERT_FILE && TLS_KEY_FILE);

function requestHandler(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ service: 'renkervault-relay', plaintextAccess: false }));
}

const server = useTls
  ? https.createServer({ cert: fs.readFileSync(TLS_CERT_FILE), key: fs.readFileSync(TLS_KEY_FILE) }, requestHandler)
  : http.createServer(requestHandler);

function verifyClient(info, cb) {
  const origin = info.req.headers.origin;
  // No Origin header (native clients like Tauri/Android usually send
  // no browser-typical origin) -> not checkable, let through.
  if (!origin || ALLOWED_ORIGINS.length === 0) return cb(true);
  if (ALLOWED_ORIGINS.includes(origin)) return cb(true);
  cb(false, 403, 'origin-not-allowed');
}

const wss = new WebSocketServer({ server, maxPayload: MAX_MSG_BYTES, verifyClient });

function clientIp(req) {
  if (TRUST_PROXY) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return String(fwd).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

wss.on('connection', (ws, req) => {
  const ip = clientIp(req);
  const count = (connsByIp.get(ip) || 0) + 1;
  connsByIp.set(ip, count);
  if (count > MAX_CONNS_PER_IP) {
    send(ws, { type: 'error', error: 'too-many-connections' });
    ws.close();
    return;
  }

  const meta = { userId: null, deviceId: null, authed: false, nonce: null, msgTimes: [], ip };
  sockets.set(ws, meta);

  const authTimer = setTimeout(() => {
    if (!meta.authed) ws.close();
  }, AUTH_TIMEOUT_MS);

  ws.on('message', (raw) => {
    const t = now();
    meta.msgTimes = meta.msgTimes.filter((x) => t - x < 1000);
    meta.msgTimes.push(t);
    if (meta.msgTimes.length > 30) { send(ws, { type: 'error', error: 'rate-limited' }); return; }

    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    try {
      handle(ws, meta, msg);
    } catch (err) {
      console.error('[ERR]', err.message);
      send(ws, { type: 'error', error: 'internal' });
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimer);
    const n = (connsByIp.get(ip) || 1) - 1;
    if (n <= 0) connsByIp.delete(ip); else connsByIp.set(ip, n);
    if (meta.authed) {
      const u = users.get(meta.userId);
      const d = u?.devices.get(meta.deviceId);
      if (d) d.lastSeen = now();
    }
    sockets.delete(ws);
  });
});

function handle(ws, meta, msg) {
  switch (msg.type) {
    case 'hello': {
      const { userId, deviceId, deviceName, edPub, xPub, prekeyPub, pqPrekeyPub, prekeySig, pqPrekeySig } = msg;
      if (!userId || !deviceId || !edPub || !xPub) return send(ws, { type: 'error', error: 'bad-hello' });

      const g = guard(userId);
      if (g.lockedUntil > now()) {
        return send(ws, { type: 'locked', until: g.lockedUntil });
      }

      const u = getUser(userId);
      const existing = u.devices.get(deviceId);
      const isFirstDevice = u.devices.size === 0;

      if (!existing) {
        u.devices.set(deviceId, {
          deviceId,
          name: deviceName || 'Unnamed device',
          edPub,
          xPub,
          prekeyPub: prekeyPub || null,
          pqPrekeyPub: pqPrekeyPub || null,
          prekeySig: prekeySig || null,
          pqPrekeySig: pqPrekeySig || null,
          otpks: new Map(),
          trusted: isFirstDevice,
          createdAt: now(),
          lastSeen: now(),
        });
        if (!isFirstDevice) {
          securityEvent(userId, 'new-device', { deviceId, name: deviceName || 'Unnamed device' });
          console.log(`[GUARD] New device for ${userId}: ${deviceName} (awaiting confirmation)`);
        }
      } else if (existing.edPub !== edPub) {
        securityEvent(userId, 'key-mismatch', { deviceId });
        return send(ws, { type: 'error', error: 'key-mismatch' });
      } else {
        if (prekeyPub) existing.prekeyPub = prekeyPub;
        if (pqPrekeyPub) existing.pqPrekeyPub = pqPrekeyPub;
        if (prekeySig) existing.prekeySig = prekeySig;
        if (pqPrekeySig) existing.pqPrekeySig = pqPrekeySig;
      }

      meta.userId = userId;
      meta.deviceId = deviceId;
      meta.nonce = crypto.randomBytes(32).toString('base64');
      send(ws, { type: 'challenge', nonce: meta.nonce });
      break;
    }

    case 'proof': {
      if (!meta.userId || !meta.nonce) return send(ws, { type: 'error', error: 'no-challenge' });
      const g = guard(meta.userId);
      if (g.lockedUntil > now()) return send(ws, { type: 'locked', until: g.lockedUntil });

      const u = getUser(meta.userId);
      const dev = u.devices.get(meta.deviceId);
      let ok = false;
      try {
        ok = ed25519.verify(b64.dec(msg.sig), b64.dec(meta.nonce), b64.dec(dev.edPub));
      } catch { ok = false; }

      if (!ok) {
        recordAuthFail(meta.userId, dev?.name);
        return send(ws, { type: 'auth-failed' });
      }

      meta.authed = true;
      meta.nonce = null;
      dev.lastSeen = now();
      send(ws, { type: 'authed', trusted: dev.trusted, deviceId: meta.deviceId });

      if (dev.trusted && u.queue.length) {
        for (const env of u.queue) send(ws, env);
        u.queue = [];
      }
      break;
    }

    case 'report-unlock-fail': {
      if (!meta.userId) return;
      recordAuthFail(meta.userId, msg.device || 'local');
      break;
    }

    case 'send': {
      if (!meta.authed) return send(ws, { type: 'error', error: 'not-authed' });
      if (!checkRate(sendRateByAccount, meta.userId, SEND_RATE_LIMIT, SEND_RATE_WINDOW_MS)) {
        return send(ws, { type: 'error', error: 'account-rate-limited' });
      }
      const { to, envelope } = msg;
      if (!to || !envelope || typeof envelope.ct !== 'string') {
        return send(ws, { type: 'error', error: 'bad-envelope' });
      }
      const sealed = !!envelope.tag && !envelope.x3dh;
      const out = { type: 'deliver', from: sealed ? null : meta.userId, envelope, ts: now() };
      const target = users.get(to);
      if (target && hasTrustedOnlineDevice(to, target)) {
        toTrustedUser(to, out, target);
      } else if (target) {
        if (target.queue.length < MAX_QUEUE) target.queue.push(out);
      } else {
        if (users.size >= MAX_TRACKED_USERS) return send(ws, { type: 'error', error: 'unknown-recipient' });
        const t = getUser(to);
        if (t.queue.length < MAX_QUEUE) t.queue.push(out);
      }
      send(ws, { type: 'sent', ref: msg.ref ?? null });
      break;
    }

    case 'devices': {
      if (!meta.authed) return;
      const u = getUser(meta.userId);
      const onlineIds = new Set(
        [...sockets.values()].filter((m) => m.authed && m.userId === meta.userId).map((m) => m.deviceId)
      );
      send(ws, {
        type: 'devices',
        devices: [...u.devices.values()].map((d) => ({
          deviceId: d.deviceId,
          name: d.name,
          trusted: d.trusted,
          createdAt: d.createdAt,
          lastSeen: d.lastSeen,
          online: onlineIds.has(d.deviceId),
          current: d.deviceId === meta.deviceId,
        })),
      });
      break;
    }

    case 'approve-device': {
      if (!meta.authed) return;
      const u = getUser(meta.userId);
      const caller = u.devices.get(meta.deviceId);
      // Only an already-confirmed device may approve further devices — otherwise
      // a self-registered, never-confirmed device could simply self-
      // approve (the deviceId is always known to the caller) and fully bypass the
      // entire confirmation step.
      if (!caller || !caller.trusted) return send(ws, { type: 'error', error: 'not-trusted' });
      const d = u.devices.get(msg.deviceId);
      if (d) {
        d.trusted = true;
        securityEvent(meta.userId, 'device-approved', { deviceId: d.deviceId, name: d.name });
      }
      break;
    }

    case 'revoke-device': {
      if (!meta.authed) return;
      const u = getUser(meta.userId);
      const caller = u.devices.get(meta.deviceId);
      // Same rationale as for approve-device: otherwise a non-confirmed
      // device could throw out the real, trusted devices of the account
      // (account takeover / denial-of-service).
      if (!caller || !caller.trusted) return send(ws, { type: 'error', error: 'not-trusted' });
      if (u.devices.delete(msg.deviceId)) {
        for (const [sock, m] of sockets) {
          if (m.userId === meta.userId && m.deviceId === msg.deviceId) {
            send(sock, { type: 'revoked' });
            sock.close();
          }
        }
        securityEvent(meta.userId, 'device-revoked', { deviceId: msg.deviceId });
      }
      break;
    }

    case 'lookup': {
      if (!meta.authed) return;
      if (!checkRate(lookupRate, meta.userId, LOOKUP_RATE_LIMIT, LOOKUP_RATE_WINDOW_MS)) {
        return send(ws, { type: 'error', error: 'lookup-rate-limited', ref: msg.ref ?? null });
      }
      const target = users.get(msg.userId);
      // Only an already-confirmed device may be delivered as a handshake bundle for new
      // contacts — otherwise a non-confirmed, purely self-registered
      // device could hijack new conversations.
      const first = target ? [...target.devices.values()].find((d) => d.trusted) ?? null : null;
      let otpk = null;
      if (first && msg.forHandshake === true && first.otpks.size > 0) {
        if (!checkRate(otpkLookupRate, meta.userId, OTPK_LOOKUP_RATE_LIMIT, OTPK_LOOKUP_RATE_WINDOW_MS)) {
          return send(ws, { type: 'error', error: 'lookup-rate-limited', ref: msg.ref ?? null });
        }
        const [id] = first.otpks.keys();
        const pub = first.otpks.get(id);
        first.otpks.delete(id);
        otpk = { id, pub };
      }
      send(ws, {
        type: 'lookup-result',
        userId: msg.userId,
        found: !!first,
        edPub: first?.edPub ?? null,
        xPub: first?.xPub ?? null,
        prekeyPub: first?.prekeyPub ?? null,
        pqPrekeyPub: first?.pqPrekeyPub ?? null,
        prekeySig: first?.prekeySig ?? null,
        pqPrekeySig: first?.pqPrekeySig ?? null,
        otpk,
        ref: msg.ref ?? null,
      });
      break;
    }

    case 'publish-otpks': {
      if (!meta.authed) return;
      const u = getUser(meta.userId);
      const dev = u.devices.get(meta.deviceId);
      if (!dev || !Array.isArray(msg.keys)) return;
      const keys = msg.keys.slice(0, MAX_OTPK_PER_PUBLISH);
      for (const k of keys) {
        if (!k || typeof k.id !== 'string' || typeof k.pub !== 'string') continue;
        if (dev.otpks.size >= MAX_OTPK_PER_DEVICE) break;
        if (!dev.otpks.has(k.id)) dev.otpks.set(k.id, k.pub);
      }
      break;
    }

    default:
      send(ws, { type: 'error', error: 'unknown-type' });
  }
}

setInterval(sweep, SWEEP_INTERVAL_MS).unref();

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  server.listen(PORT, HOST, () => {
    const scheme = useTls ? 'wss' : 'ws';
    const displayHost = HOST === '0.0.0.0' ? 'localhost' : HOST;
    console.log(`RenkerVault relay running on ${scheme}://${displayHost}:${PORT} (bound to ${HOST})`);
    console.log(`TLS: ${useTls ? 'ON (native certificate)' : 'OFF — only suitable for local use/reverse-proxy setup, see deploy/DEPLOYMENT.md'}`);
    console.log('Content-blind mode: the server stores ciphertext only.');
  });
}

export { server, sweep, users, MAX_TRACKED_USERS, QUEUE_TTL_MS };
