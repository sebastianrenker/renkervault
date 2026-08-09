import { RatchetSnapshot } from '../crypto/ratchet';

export type ChatKind = 'direct' | 'group' | 'channel';

export type ChatOrigin = 'demo' | 'real';

export type ThemeName = 'default' | 'dark' | 'oled' | 'light' | 'cyber' | 'minimal';

export interface ReplyRef {
  id: string;
  fromName: string;
  preview: string;
}

export interface Message {
  id: string;
  from: string;
  fromName: string;
  body: string;
  ct: string;
  ts: number;
  own: boolean;
  kind: 'text' | 'file' | 'system';
  fileName?: string;
  fileSize?: number;
  fileMime?: string;
  fileDataUrl?: string;
  expiresAt?: number;
  readByPeer?: boolean;
  replyTo?: ReplyRef;
  edited?: boolean;
  deleted?: boolean;
  reactions?: Record<string, string[]>;
  forwardedFrom?: string;
}

export interface MemberPermissions {
  canPost: boolean;
  canInvite: boolean;
  canRemove: boolean;
  canPin: boolean;
}

export interface Member {
  id: string;
  name: string;
  role: 'owner' | 'admin' | 'member';
  permissions?: MemberPermissions;
}

export interface Chat {
  id: string;
  kind: ChatKind;
  origin: ChatOrigin;
  name: string;
  sub: string;
  members: Member[];
  safetyNumber: string;
  shortFp: string;
  verified: boolean;
  disappearSec: number;
  epoch: number;
  keyRotatedAt: number;
  subscriberCount?: number;
  unread: number;
  pinned?: boolean;
  muted?: boolean;
  archived?: boolean;
  pinnedMessageId?: string | null;
}

export type Severity = 'info' | 'warn' | 'alert';

export interface SecEvent {
  id: string;
  ts: number;
  severity: Severity;
  kind: string;
  text: string;
  device?: string;
}

export interface DeviceInfo {
  id: string;
  name: string;
  trusted: boolean;
  online: boolean;
  current: boolean;
  createdAt: number;
  lastSeen: number;
}

export interface Settings {
  theme: ThemeName;
  accent: string;
  readReceipts: boolean;
  typingIndicator: boolean;
  alarmSound: boolean;
  autoLockdown: boolean;
  coverTraffic: boolean;
  relayUrl: string;
}

export interface Identity {
  userId: string;
  displayName: string;
  xPriv: string; xPub: string;
  edPriv: string; edPub: string;
  prekeyPriv: string; prekeyPub: string;
  pqPrekeyPriv: string; pqPrekeyPub: string;
  deviceId: string;
  deviceName: string;
}

export interface Contact {
  userId: string;
  name: string;
  edPub: string;
  xPub: string;
  prekeyPub: string;
  pqPrekeyPub: string;
  addedAt: number;
  verified: boolean;
  online?: boolean;
  lastSeen?: number;
}

export interface StoredSession {
  peerUserId: string;
  ratchet: RatchetSnapshot;
  initiator: boolean;
  handshakeSent: boolean;
  tag: string;
}

export interface VaultData {
  identity: Identity;
  settings: Settings;
  chats: Chat[];
  messages: Record<string, Message[]>;
  secLog: SecEvent[];
  demoPeerKeys: Record<string, { priv: string; pub: string; name: string }>;
  contacts: Record<string, Contact>;
  sessions: Record<string, StoredSession>;
  groupKeys: Record<string, { key: string; epoch: number }>;
  oneTimePrekeys: Record<string, { priv: string; pub: string }>;
}

export interface AlarmState {
  active: boolean;
  reason: string;
  kind: string;
  ts: number;
  lockdown: boolean;
}

export const DEFAULT_RELAY_URL = 'ws://localhost:8787';

export const DEFAULT_SETTINGS: Settings = {
  theme: 'default',
  accent: '#0a84ff',
  readReceipts: false,
  typingIndicator: false,
  alarmSound: true,
  autoLockdown: true,
  coverTraffic: true,
  relayUrl: DEFAULT_RELAY_URL,
};

export const ACCENTS = ['#0a84ff', '#5e5ce6', '#30b955', '#ff9500', '#ff375f', '#64748b'];

export const THEMES: { id: ThemeName; label: string }[] = [
  { id: 'default', label: 'Default' },
  { id: 'dark', label: 'Dark' },
  { id: 'oled', label: 'OLED' },
  { id: 'light', label: 'Light' },
  { id: 'cyber', label: 'Cyber' },
  { id: 'minimal', label: 'Minimal' },
];

export function uid(prefix = ''): string {
  const u = crypto.getRandomValues(new Uint8Array(6));
  return prefix + [...u].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export function newUserId(): string {
  const u = crypto.getRandomValues(new Uint8Array(4));
  const hx = [...u].map((x) => x.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `RV-${hx.slice(0, 4)}-${hx.slice(4, 8)}`;
}
