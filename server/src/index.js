/**
 * RenkerVault Relay Server ("Zero-Knowledge"-Relay)
 * =================================================
 * SICHERHEITSMODELL:
 *  - Dieser Server sieht und speichert NIEMALS Klartext von Nachrichten.
 *  - Er kennt nur: Konto-IDs, oeffentliche Schluessel, Geraete-Metadaten
 *    und opake, Ende-zu-Ende-verschluesselte Envelopes (Chiffretext).
 *  - Authentifizierung erfolgt passwortlos per Ed25519-Challenge-Response:
 *    der Server erhaelt nie eine Passphrase, nur Signaturen.
 *  - Nachrichten fuer Offline-Empfaenger werden nur als Chiffretext
 *    im Arbeitsspeicher zwischengespeichert (Prototyp; kein Persistenz-Layer).
 *
 * PROTOTYP-HINWEIS: In Produktion gehoeren Konten-/Routing-Metadaten in
 * PostgreSQL und die Offline-Queue in einen persistenten Store. Fuer den
 * lokal startbaren Prototyp wird bewusst In-Memory-State verwendet.
 */
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';
import { ed25519 } from '@noble/curves/ed25519';

// ---------------------------------------------------------------------------
// Konfiguration (Umgebungsvariablen — siehe deploy/.env.example)
// ---------------------------------------------------------------------------
const PORT = process.env.PORT ? Number(process.env.PORT) : 8787;
const HOST = process.env.HOST || '0.0.0.0';
const TLS_CERT_FILE = process.env.TLS_CERT_FILE || '';
const TLS_KEY_FILE = process.env.TLS_KEY_FILE || '';
// Hinter einem Reverse-Proxy (Caddy/nginx) steht die echte Client-IP in
// X-Forwarded-For; nur aktivieren, wenn der Proxy vertrauenswuerdig ist,
// sonst koennten Clients ihre eigene IP vortaeuschen (Rate-Limit-Umgehung).
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

// ---------------------------------------------------------------------------
// In-Memory-State (nur Metadaten + Chiffretext, nie Klartext)
// ---------------------------------------------------------------------------
/** userId -> { devices: Map<deviceId, DeviceRecord>, queue: Envelope[] } */
const users = new Map();
/** userId -> { fails: number[], lockedUntil: number } (Brute-Force-Erkennung) */
const authGuard = new Map();
/** ws -> { userId, deviceId, authed } */
const sockets = new Map();
/** IP -> Anzahl aktuell offener Sockets (Basisschutz gegen Verbindungsflut) */
const connsByIp = new Map();
/** Konto-ID -> Zeitstempel gesendeter Nachrichten (kontoweites Rate-Limit,
 *  UNABHAENGIG vom Pro-Socket-Limit — verhindert, dass ein Konto mit vielen
 *  gleichzeitig verbundenen Geraeten das Pro-Socket-Limit einfach durch
 *  mehr Sockets umgeht und z. B. die Warteschlange eines Ziel-Kontos flutet). */
const sendRateByAccount = new Map();
/** Konto-ID -> Zeitstempel von Lookups MIT forHandshake=true. Begrenzt einen
 *  gezielten "One-Time-Prekey-Exhaustion"-Angriff: Ohne dieses Limit koennte
 *  ein boeswilliger Akteur den kompletten OTPK-Bestand eines Opfers durch
 *  schnell wiederholte Lookups verbrauchen (Kapitel "Volles X3DH", siehe
 *  net/realchat.ts) und dessen kuenftige Handshakes so dauerhaft auf die
 *  schwaechere 2-DH-Variante zwingen. Normale Nutzung (neue Kontakte
 *  hinzufuegen) braucht dieses Limit nie auszureizen. */
const otpkLookupRate = new Map();

const FAIL_WINDOW_MS = 5 * 60 * 1000; // 5 Minuten
const FAIL_LIMIT = 5;                 // 5 Fehlversuche -> Lockout
const LOCKOUT_MS = 60 * 1000;         // 60 Sekunden Lockout
const MAX_QUEUE = 500;                // Offline-Queue-Limit pro Nutzer
const MAX_MSG_BYTES = 2 * 1024 * 1024; // 2 MB pro Envelope (Anhaenge/Sprachnachrichten inline, Base64+JSON-Aufschlag eingerechnet)
const MAX_CONNS_PER_IP = 20;          // Basisschutz gegen Verbindungsflut von einer IP
const AUTH_TIMEOUT_MS = 15 * 1000;    // Unauthentifizierte Sockets nach 15s trennen
const MAX_OTPK_PER_DEVICE = 100;      // Obergrenze fuer den One-Time-Prekey-Bestand eines Geraets
const MAX_OTPK_PER_PUBLISH = 50;      // Obergrenze pro einzelner publish-otpks-Nachricht
const SEND_RATE_WINDOW_MS = 60 * 1000; // Zeitfenster fuer das kontoweite Sende-Limit
const SEND_RATE_LIMIT = 300;           // max. Nachrichten pro Konto und Zeitfenster (~5/s im Schnitt)
const OTPK_LOOKUP_RATE_WINDOW_MS = 5 * 60 * 1000; // Zeitfenster fuer das Handshake-Lookup-Limit
const OTPK_LOOKUP_RATE_LIMIT = 20;     // max. forHandshake-Lookups pro Konto und Zeitfenster

const b64 = {
  dec: (s) => Uint8Array.from(Buffer.from(s, 'base64')),
};

function now() { return Date.now(); }

/** Generisches Sliding-Window-Rate-Limit: true = erlaubt (und mitgezaehlt),
 *  false = Limit erreicht (Aufruf wird NICHT mitgezaehlt). */
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
    u = { devices: new Map(), queue: [] };
    users.set(userId, u);
  }
  return u;
}

function guard(userId) {
  let g = authGuard.get(userId);
  if (!g) { g = { fails: [], lockedUntil: 0 }; authGuard.set(userId, g); }
  return g;
}

/** Sendet an alle authentifizierten Sockets eines Nutzers. */
function toUser(userId, msg, exceptWs = null) {
  const data = JSON.stringify(msg);
  for (const [ws, meta] of sockets) {
    if (meta.authed && meta.userId === userId && ws !== exceptWs && ws.readyState === 1) {
      ws.send(data);
    }
  }
}

function send(ws, msg) {
  if (ws.readyState === 1) ws.send(JSON.stringify(msg));
}

/** Sicherheitsereignis an alle Geraete eines Kontos melden. */
function securityEvent(userId, kind, detail) {
  toUser(userId, { type: 'security-event', kind, detail, ts: now() });
}

/**
 * Registriert einen Auth-Fehlversuch. Loest bei Ueberschreitung
 * des Limits einen Lockout + Alarm-Broadcast aus.
 */
function recordAuthFail(userId, deviceHint) {
  const g = guard(userId);
  const t = now();
  g.fails = g.fails.filter((f) => t - f < FAIL_WINDOW_MS);
  g.fails.push(t);
  securityEvent(userId, 'auth-fail', {
    attempts: g.fails.length,
    device: deviceHint || 'unbekannt',
  });
  if (g.fails.length >= FAIL_LIMIT) {
    g.lockedUntil = t + LOCKOUT_MS;
    g.fails = [];
    securityEvent(userId, 'lockout', { until: g.lockedUntil, seconds: LOCKOUT_MS / 1000 });
    console.log(`[GUARD] Lockout fuer ${userId} (${FAIL_LIMIT} Fehlversuche)`);
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// HTTP + WebSocket
// ---------------------------------------------------------------------------
const useTls = !!(TLS_CERT_FILE && TLS_KEY_FILE);

function requestHandler(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ service: 'renkervault-relay', plaintextAccess: false }));
}

const server = useTls
  ? https.createServer({ cert: fs.readFileSync(TLS_CERT_FILE), key: fs.readFileSync(TLS_KEY_FILE) }, requestHandler)
  : http.createServer(requestHandler);

const wss = new WebSocketServer({ server, maxPayload: MAX_MSG_BYTES });

/** Client-IP ermitteln — respektiert X-Forwarded-For nur, wenn TRUST_PROXY gesetzt ist. */
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

  // Sockets, die sich nie authentifizieren, nach kurzer Zeit trennen
  // (verhindert offene, ungenutzte Verbindungen als Ressourcen-Bindung).
  const authTimer = setTimeout(() => {
    if (!meta.authed) ws.close();
  }, AUTH_TIMEOUT_MS);

  ws.on('message', (raw) => {
    // Einfaches Rate-Limit pro Socket (30 Nachrichten/Sekunde)
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
    // -- Schritt 1: Client meldet sich mit Konto/Geraet + oeffentlichen Schluesseln --
    case 'hello': {
      const { userId, deviceId, deviceName, edPub, xPub, prekeyPub, pqPrekeyPub } = msg;
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
          name: deviceName || 'Unbenanntes Geraet',
          edPub,
          xPub,
          prekeyPub: prekeyPub || null,
          pqPrekeyPub: pqPrekeyPub || null,
          // One-Time-Prekeys fuer volles X3DH (siehe 'publish-otpks' und
          // 'lookup' unten): id -> oeffentlicher Schluessel. Jeder Eintrag
          // wird bei einem forHandshake-Lookup genau EINMAL herausgegeben
          // und danach sofort aus dieser Map entfernt.
          otpks: new Map(),
          // Erstes Geraet ist automatisch vertrauenswuerdig,
          // jedes weitere braucht manuelle Bestaetigung (Intrusion-Schutz).
          trusted: isFirstDevice,
          createdAt: now(),
          lastSeen: now(),
        });
        if (!isFirstDevice) {
          securityEvent(userId, 'new-device', { deviceId, name: deviceName || 'Unbenanntes Geraet' });
          console.log(`[GUARD] Neues Geraet fuer ${userId}: ${deviceName} (wartet auf Bestaetigung)`);
        }
      } else if (existing.edPub !== edPub) {
        // Geraete-ID mit anderem Schluessel -> moeglicher Angriff
        securityEvent(userId, 'key-mismatch', { deviceId });
        return send(ws, { type: 'error', error: 'key-mismatch' });
      } else {
        if (prekeyPub) existing.prekeyPub = prekeyPub; // Prekey kann rotieren, Identity bleibt gleich
        if (pqPrekeyPub) existing.pqPrekeyPub = pqPrekeyPub;
      }

      meta.userId = userId;
      meta.deviceId = deviceId;
      meta.nonce = crypto.randomBytes(32).toString('base64');
      send(ws, { type: 'challenge', nonce: meta.nonce });
      break;
    }

    // -- Schritt 2: Client beweist Schluesselbesitz per Signatur --
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

      // Offline-Queue zustellen (nur Chiffretext)
      if (dev.trusted && u.queue.length) {
        for (const env of u.queue) send(ws, env);
        u.queue = [];
      }
      break;
    }

    // -- Client meldet einen fehlgeschlagenen LOKALEN Entsperrversuch --
    // (Vault-Passphrase falsch). Der Server kennt die Passphrase nicht,
    // zaehlt aber Fehlversuche kontouebergreifend fuer den Lockout.
    case 'report-unlock-fail': {
      if (!meta.userId) return;
      recordAuthFail(meta.userId, msg.device || 'lokal');
      break;
    }

    // -- E2E-verschluesselte Nachricht routen (Server sieht nur Chiffretext) --
    case 'send': {
      if (!meta.authed) return send(ws, { type: 'error', error: 'not-authed' });
      if (!checkRate(sendRateByAccount, meta.userId, SEND_RATE_LIMIT, SEND_RATE_WINDOW_MS)) {
        return send(ws, { type: 'error', error: 'account-rate-limited' });
      }
      const { to, envelope } = msg;
      if (!to || !envelope || typeof envelope.ct !== 'string') {
        return send(ws, { type: 'error', error: 'bad-envelope' });
      }
      // "Sealed Sender" fuer Folgenachrichten einer bereits bestehenden
      // Sitzung: traegt das Envelope ein Sealed-Sender-Tag (client/src/
      // net/realchat.ts: deriveSessionTag) UND ist es KEIN Erstkontakt
      // (kein x3dh-Feld), wird die Konto-ID des Absenders NICHT in die
      // zugestellte/zwischengespeicherte Nachricht geschrieben — der
      // Empfaenger loest sie stattdessen selbst ueber das Tag auf. Bei
      // Erstkontakt-Nachrichten (x3dh gesetzt) kennt die Gegenseite das Tag
      // noch nicht und braucht die Konto-ID zwingend, um ueberhaupt antworten
      // zu koennen. Der Relay selbst kennt den Absender an dieser Stelle
      // dennoch immer ueber die authentifizierte Verbindung (meta.userId) —
      // dieses Feld reduziert also, was in der zugestellten/gespeicherten
      // Nachricht landet, nicht die Sicht des Betreibers auf die live
      // eingehende Verbindung selbst (siehe SECURITY.md Punkt 7).
      const sealed = !!envelope.tag && !envelope.x3dh;
      const out = { type: 'deliver', from: sealed ? null : meta.userId, envelope, ts: now() };
      const target = users.get(to);
      const online = [...sockets.values()].some((m) => m.authed && m.userId === to);
      if (online) {
        toUser(to, out);
      } else if (target) {
        if (target.queue.length < MAX_QUEUE) target.queue.push(out);
      } else {
        // Unbekannter Empfaenger: Queue anlegen (Konto ggf. spaeter registriert)
        const t = getUser(to);
        if (t.queue.length < MAX_QUEUE) t.queue.push(out);
      }
      send(ws, { type: 'sent', ref: msg.ref ?? null });
      break;
    }

    // -- Geraeteverwaltung --
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
      if (u.devices.delete(msg.deviceId)) {
        // Aktive Sockets dieses Geraets sofort trennen
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

    // -- Oeffentliche Schluessel eines Kontakts abfragen (fuer Schluesselaustausch) --
    case 'lookup': {
      if (!meta.authed) return;
      const target = users.get(msg.userId);
      const first = target ? [...target.devices.values()][0] : null;
      // Ein One-Time-Prekey wird NUR verbraucht, wenn der Anfragende explizit
      // signalisiert, direkt im Anschluss einen Handshake zu beginnen — ein
      // reiner Info-Lookup (z. B. Kontaktname auffrischen) soll keinen
      // wertvollen Einmal-Prekey aus dem Bestand der Gegenseite verbrauchen.
      // Zusaetzlich eigens rate-limitiert (OTPK_LOOKUP_RATE_LIMIT), damit ein
      // boeswilliger Akteur nicht durch schnell wiederholte Handshake-Lookups
      // gezielt den gesamten OTPK-Bestand eines Opfers leerraeumt.
      let otpk = null;
      if (first && msg.forHandshake === true && first.otpks.size > 0) {
        if (!checkRate(otpkLookupRate, meta.userId, OTPK_LOOKUP_RATE_LIMIT, OTPK_LOOKUP_RATE_WINDOW_MS)) {
          return send(ws, { type: 'error', error: 'lookup-rate-limited', ref: msg.ref ?? null });
        }
        const [id] = first.otpks.keys();
        const pub = first.otpks.get(id);
        first.otpks.delete(id); // ab hier fuer IMMER vergeben, kein zweites Mal ausgegeben
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
        otpk,
        ref: msg.ref ?? null,
      });
      break;
    }

    // -- Client hinterlegt (weitere) eigene One-Time-Prekeys fuer volles X3DH --
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

server.listen(PORT, HOST, () => {
  const scheme = useTls ? 'wss' : 'ws';
  const displayHost = HOST === '0.0.0.0' ? 'localhost' : HOST;
  console.log(`RenkerVault Relay laeuft auf ${scheme}://${displayHost}:${PORT} (gebunden an ${HOST})`);
  console.log(`TLS: ${useTls ? 'AKTIV (natives Zertifikat)' : 'AUS — nur fuer lokale Nutzung/Reverse-Proxy-Setup geeignet, siehe deploy/DEPLOYMENT.md'}`);
  console.log('Zero-Knowledge-Modus: Server speichert ausschliesslich Chiffretext.');
});
