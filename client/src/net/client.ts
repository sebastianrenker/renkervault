/**
 * Relay-Client (WebSocket zum Zero-Knowledge-Relay, server/src/index.js).
 * ======================================================================
 * Der Relay sieht ausschließlich: Konto-ID, Geräte-Metadaten, öffentliche
 * Schlüssel und opake Envelopes. Authentifizierung passwortlos per
 * Ed25519-Challenge-Response — die Passphrase verlässt den Client nie.
 *
 * Die App funktioniert auch OHNE Relay (lokaler Demo-Modus); der Relay
 * liefert dann zusätzlich: echte Geräteliste, Geräte-Freigabe/-Widerruf,
 * serverseitige Brute-Force-Erkennung, kontoweite Security-Events UND
 * die echte Zustellung Ende-zu-Ende-verschlüsselter Envelopes zwischen
 * echten Nutzern (Kontakte/Gruppen, siehe net/realchat.ts).
 */
import { b64, edSign } from '../crypto/primitives';
import { Identity, ReplyRef } from '../state/types';

export type RelayStatus = 'offline' | 'connecting' | 'online' | 'locked';

/** Opakes Envelope, wie es der Relay unverändert weiterreicht (nur Chiffretext
 *  + Routing-Metadaten — niemals Klartext). Felder über 'ct' hinaus dienen
 *  dem EMPFANGENDEN Client dazu, die Nachricht der richtigen Sitzung/Gruppe
 *  zuzuordnen; der Relay selbst interpretiert sie nicht.
 *
 *  'edit' | 'delete' | 'reaction' | 'presence' sind reine Anwendungs-Events,
 *  die wie normale Nachrichten Ende-zu-Ende-verschlüsselt über bestehende
 *  1:1-/Gruppen-Sitzungen laufen (kein separater Server-Mechanismus nötig). */
export interface Envelope {
  ct: string;
  chatId: string;
  chatKind: 'direct' | 'group';
  kind: 'text' | 'file' | 'group-key' | 'system' | 'edit' | 'delete' | 'reaction' | 'presence';
  msgId: string;
  ts: number;
  fromName: string;
  fileName?: string;
  fileSize?: number;
  fileMime?: string;
  expiresAt?: number;
  replyTo?: ReplyRef;
  forwardedFrom?: string;
  targetMsgId?: string;      // Bezug für edit/delete/reaction
  emoji?: string;            // nur 'reaction'
  reactionOp?: 'add' | 'remove'; // nur 'reaction'
  presence?: 'online' | 'offline'; // nur 'presence'
  header?: { dh: string; pn: number; n: number }; // nur 1:1 (Ratchet)
  epoch?: number;                                 // nur Gruppe (Epoch-Key)
  /** Nur allererste 1:1-Nachricht: X3DH-Handshake, hybrid um ML-KEM-768
   *  ergänzt (pqCt = Kyber-Ciphertext) — siehe crypto/pq.ts. otpkId verweist
   *  auf den beim Lookup verbrauchten One-Time-Prekey des Empfängers
   *  (volles X3DH, siehe net/realchat.ts) — fehlt er, war beim Lookup
   *  keiner mehr verfügbar und der Handshake nutzt nur den Signed Prekey. */
  x3dh?: { ephPub: string; identityPub: string; pqCt: string; otpkId?: string };
  /** Sealed-Sender-Tag für 1:1-Folgenachrichten (net/realchat.ts:
   *  deriveSessionTag) — der Relay routet damit statt anhand der Konto-ID
   *  des Absenders und liefert dann `from: null` aus (server/src/index.js,
   *  Fall 'send'). Nur ab der zweiten Nachricht einer Sitzung gesetzt. */
  tag?: string;
}

export interface LookupResult {
  userId: string;
  found: boolean;
  edPub: string | null;
  xPub: string | null;
  prekeyPub: string | null;
  pqPrekeyPub: string | null;
  /** Nur gesetzt, wenn forHandshake=true angefragt wurde UND der Relay noch
   *  einen unverbrauchten One-Time-Prekey auf Lager hatte. Der Relay merkt
   *  sich diesen Prekey NICHT mehr, sobald er einmal herausgegeben wurde. */
  otpk: { id: string; pub: string } | null;
}

export interface RelayEvents {
  onStatus(status: RelayStatus): void;
  onSecurityEvent(kind: string, detail: Record<string, unknown>, ts: number): void;
  onDevices(devices: Array<{
    deviceId: string; name: string; trusted: boolean;
    createdAt: number; lastSeen: number; online: boolean; current: boolean;
  }>): void;
  onRevoked(): void;
  /** Echte, verschlüsselte Nachricht eines anderen Nutzers zugestellt.
   *  `from` ist NULL bei Sealed-Sender-Folgenachrichten (envelope.tag
   *  gesetzt) — der Empfänger löst die Konto-ID dann selbst über
   *  realChat.resolvePeerByTag(envelope.tag) auf, statt sich auf den Relay
   *  zu verlassen (siehe net/realchat.ts). */
  onDeliver(from: string | null, envelope: Envelope): void;
}

const LOOKUP_TIMEOUT_MS = 6000;

export class RelayClient {
  private ws: WebSocket | null = null;
  private identity: Identity | null = null;
  private events: RelayEvents;
  private pendingLookups = new Map<string, { resolve: (r: LookupResult) => void }>();
  status: RelayStatus = 'offline';

  constructor(events: RelayEvents) {
    this.events = events;
  }

  /** @param relayUrl ws(s)://host:port des Relays — konfigurierbar in den Einstellungen. */
  connect(identity: Identity, relayUrl: string): void {
    this.identity = identity;
    this.setStatus('connecting');
    try {
      this.ws = new WebSocket(relayUrl);
    } catch {
      this.setStatus('offline');
      return;
    }
    const ws = this.ws;

    ws.onopen = () => {
      this.send({
        type: 'hello',
        userId: identity.userId,
        deviceId: identity.deviceId,
        deviceName: identity.deviceName,
        edPub: identity.edPub,
        xPub: identity.xPub,
        prekeyPub: identity.prekeyPub,
        pqPrekeyPub: identity.pqPrekeyPub,
      });
    };

    ws.onmessage = (ev) => {
      let msg: any;
      try { msg = JSON.parse(String(ev.data)); } catch { return; }
      switch (msg.type) {
        case 'challenge': {
          // Besitz des Ed25519-Keys beweisen, ohne Geheimnis zu übertragen
          const sig = edSign(b64.dec(msg.nonce), b64.dec(identity.edPriv));
          this.send({ type: 'proof', sig: b64.enc(sig) });
          break;
        }
        case 'authed':
          this.setStatus('online');
          this.send({ type: 'devices' });
          break;
        case 'locked':
          this.setStatus('locked');
          break;
        case 'auth-failed':
          this.setStatus('offline');
          break;
        case 'security-event':
          this.events.onSecurityEvent(msg.kind, msg.detail ?? {}, msg.ts);
          if (msg.kind === 'new-device' || msg.kind === 'device-approved' || msg.kind === 'device-revoked') {
            this.send({ type: 'devices' });
          }
          break;
        case 'devices':
          this.events.onDevices(msg.devices ?? []);
          break;
        case 'revoked':
          this.events.onRevoked();
          break;
        case 'deliver':
          if (msg.envelope && typeof msg.envelope.ct === 'string') {
            this.events.onDeliver(msg.from, msg.envelope as Envelope);
          }
          break;
        case 'lookup-result': {
          const pending = msg.ref ? this.pendingLookups.get(msg.ref) : null;
          if (pending) {
            this.pendingLookups.delete(msg.ref);
            pending.resolve({
              userId: msg.userId, found: !!msg.found,
              edPub: msg.edPub ?? null, xPub: msg.xPub ?? null, prekeyPub: msg.prekeyPub ?? null,
              pqPrekeyPub: msg.pqPrekeyPub ?? null,
              otpk: msg.otpk ?? null,
            });
          }
          break;
        }
      }
    };

    ws.onerror = () => { /* onclose folgt */ };
    ws.onclose = () => {
      if (this.status !== 'locked') this.setStatus('offline');
      this.ws = null;
    };
  }

  /** Lokalen Entsperr-Fehlversuch an den Relay melden (kontenweite Zählung). */
  reportUnlockFail(deviceName: string): void {
    this.send({ type: 'report-unlock-fail', device: deviceName });
  }

  sendEnvelope(to: string, envelope: Envelope): void {
    this.send({ type: 'send', to, envelope });
  }

  /** Öffentliche Schlüssel eines Kontos abfragen (für Kontakt hinzufügen).
   *  forHandshake=true NUR setzen, wenn direkt im Anschluss tatsächlich ein
   *  Erstkontakt-Handshake stattfindet (beginSession) — nur dann verbraucht
   *  der Relay einen One-Time-Prekey aus dem Bestand der Gegenseite. Ein
   *  reiner Info-Lookup (z. B. Kontaktname beim Empfang einer neuen
   *  Nachricht auffrischen) soll keinen wertvollen Einmal-Prekey verbrauchen. */
  lookup(userId: string, forHandshake = false): Promise<LookupResult> {
    return new Promise((resolve) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        return resolve({ userId, found: false, edPub: null, xPub: null, prekeyPub: null, pqPrekeyPub: null, otpk: null });
      }
      const ref = `lk-${Math.random().toString(36).slice(2)}`;
      this.pendingLookups.set(ref, { resolve });
      this.send({ type: 'lookup', userId, ref, forHandshake });
      setTimeout(() => {
        if (this.pendingLookups.has(ref)) {
          this.pendingLookups.delete(ref);
          resolve({ userId, found: false, edPub: null, xPub: null, prekeyPub: null, pqPrekeyPub: null, otpk: null });
        }
      }, LOOKUP_TIMEOUT_MS);
    });
  }

  /** Eigene, noch unverbrauchte One-Time-Prekeys (idempotent) beim Relay
   *  hinterlegen — siehe net/realchat.ts: topUpOneTimePrekeys(). */
  publishOneTimePrekeys(keys: { id: string; pub: string }[]): void {
    if (keys.length === 0) return;
    this.send({ type: 'publish-otpks', keys });
  }

  requestDevices(): void { this.send({ type: 'devices' }); }
  approveDevice(deviceId: string): void { this.send({ type: 'approve-device', deviceId }); }
  revokeDevice(deviceId: string): void { this.send({ type: 'revoke-device', deviceId }); }

  disconnect(): void {
    this.ws?.close();
    this.ws = null;
    this.setStatus('offline');
  }

  private send(obj: unknown): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
    }
  }

  private setStatus(s: RelayStatus): void {
    this.status = s;
    this.events.onStatus(s);
  }
}
