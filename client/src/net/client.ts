import { b64, edSign } from '../crypto/primitives';
import { Identity, ReplyRef } from '../state/types';

export type RelayStatus = 'offline' | 'connecting' | 'online' | 'locked';

export interface Envelope {
  ct: string;
  chatId: string;
  chatKind: 'direct' | 'group';
  kind: 'text' | 'file' | 'group-key' | 'system' | 'edit' | 'delete' | 'reaction' | 'presence'
      | 'call-offer' | 'call-answer' | 'call-ice' | 'call-hangup';
  msgId: string;
  ts: number;
  fromName: string;
  fileName?: string;
  fileSize?: number;
  fileMime?: string;
  expiresAt?: number;
  replyTo?: ReplyRef;
  forwardedFrom?: string;
  targetMsgId?: string;
  emoji?: string;
  reactionOp?: 'add' | 'remove';
  presence?: 'online' | 'offline';
  header?: { dh: string; pn: number; n: number };
  epoch?: number;
  x3dh?: { ephPub: string; identityPub: string; pqCt: string; otpkId?: string };
  tag?: string;
}

export interface LookupResult {
  userId: string;
  found: boolean;
  edPub: string | null;
  xPub: string | null;
  prekeyPub: string | null;
  pqPrekeyPub: string | null;
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

    ws.onerror = () => {};
    ws.onclose = () => {
      if (this.status !== 'locked') this.setStatus('offline');
      this.ws = null;
    };
  }

  reportUnlockFail(deviceName: string): void {
    this.send({ type: 'report-unlock-fail', device: deviceName });
  }

  sendEnvelope(to: string, envelope: Envelope): void {
    this.send({ type: 'send', to, envelope });
  }

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
