/** Gemeinsame Typen für Zustand & UI. */
import { RatchetSnapshot } from '../crypto/ratchet';

export type ChatKind = 'direct' | 'group' | 'channel';

/** 'demo' = simulierter Vorführ-Kontakt (In-Process); 'real' = echter
 *  Gesprächspartner über den Relay-Server mit echter Sitzung. */
export type ChatOrigin = 'demo' | 'real';

export type ThemeName = 'default' | 'dark' | 'oled' | 'light' | 'cyber' | 'minimal';

/** Minimaler Verweis auf die zitierte Nachricht (kein Nachladen nötig). */
export interface ReplyRef {
  id: string;
  fromName: string;
  preview: string;
}

export interface Message {
  id: string;
  from: string;          // Nutzer-ID des Absenders
  fromName: string;
  body: string;          // Klartext (nur im RAM / im verschlüsselten Vault)
  ct: string;            // Base64-Chiffretext wie übertragen (Nachweis E2E)
  ts: number;
  own: boolean;
  kind: 'text' | 'file' | 'system';
  fileName?: string;
  fileSize?: number;
  fileMime?: string;
  /** Entschlüsselter Anhang als data:-URL — wird (wie body bei Textnachrichten)
   *  als Klartext im verschlüsselten Vault persistiert, weil das zugehörige
   *  Ratchet-Message-Key nach Gebrauch verworfen wird (Perfect Forward
   *  Secrecy) und der Chiffretext später NICHT erneut entschlüsselbar ist. */
  fileDataUrl?: string;
  expiresAt?: number;    // verschwindende Nachrichten
  readByPeer?: boolean;  // nur relevant wenn Lesebestätigungen aktiv
  replyTo?: ReplyRef;
  edited?: boolean;
  deleted?: boolean;             // "für alle gelöscht" (Inhalt entfernt, Hülle bleibt)
  reactions?: Record<string, string[]>; // Emoji -> Nutzer-IDs
  forwardedFrom?: string;        // Name des ursprünglichen Absenders
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
  permissions?: MemberPermissions; // nur für 'admin' gepflegt; Owner hat immer alle Rechte
}

export interface Chat {
  id: string;
  kind: ChatKind;
  origin: ChatOrigin;
  name: string;
  sub: string;               // Untertitel (Status/Beschreibung)
  members: Member[];
  safetyNumber: string;      // 60-stellig (nur direct)
  shortFp: string;           // kurzer Hex-Fingerprint (HUD)
  verified: boolean;
  disappearSec: number;      // 0 = aus
  epoch: number;             // Gruppen/Kanal: Schlüssel-Epoche
  keyRotatedAt: number;
  subscriberCount?: number;  // Kanäle
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
  kind: string;    // z. B. AUTH_FAIL, NEW_DEVICE, TAMPER, KEY_ROTATION
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
  accent: string;            // Akzentfarbe (CSS)
  readReceipts: boolean;     // Standard AUS (Metadaten-Minimierung)
  typingIndicator: boolean;  // Standard AUS (Metadaten-Leck, opt-in)
  alarmSound: boolean;
  autoLockdown: boolean;     // bei Manipulationsalarm App sperren
  /** Härtungs-Roadmap Punkt 4: periodische Dummy-Nachrichten an bekannte
   *  Kontakte (siehe net/realchat.ts: coverTrafficPlaintext/isCoverTraffic).
   *  Standard AN (anders als readReceipts/typingIndicator!) — hier macht
   *  AUS die Metadaten-Lage schlechter, nicht besser. Kostet etwas
   *  Bandbreite/Akku auch im Leerlauf, daher trotzdem abschaltbar. */
  coverTraffic: boolean;
  /** ws(s)://host:port des Zero-Knowledge-Relays. Konfigurierbar, damit
   *  Desktop-/Mobile-Builds nicht zwingend auf localhost angewiesen sind. */
  relayUrl: string;
}

export interface Identity {
  userId: string;            // z. B. RV-7F3A-92C1 (keine Telefonnummer!)
  displayName: string;
  xPriv: string; xPub: string;   // X25519 (Base64) — Identitätsschlüssel
  edPriv: string; edPub: string; // Ed25519 (Base64)
  prekeyPriv: string; prekeyPub: string; // X25519 (Base64) — veröffentlichter
                                          // Prekey für asynchronen Erstkontakt (siehe crypto/ratchet.ts)
  pqPrekeyPriv: string; pqPrekeyPub: string; // ML-KEM-768 (Base64) — hybrider
                                              // Post-Quantum-Anteil des Handshakes (siehe crypto/pq.ts)
  deviceId: string;
  deviceName: string;
}

/** Ein echter Gesprächspartner (über den Relay gefunden, nicht simuliert). */
export interface Contact {
  userId: string;
  name: string;
  edPub: string;
  xPub: string;
  prekeyPub: string;
  pqPrekeyPub: string;
  addedAt: number;
  verified: boolean;
  /** Präsenz — app-seitiges Best-Effort-Signal zwischen Kontakten, das
   *  ausschließlich über bereits bestehende 1:1-Sitzungen läuft. Der Relay
   *  selbst verwaltet KEINE Kontaktliste/Präsenz (Zero-Knowledge-Prinzip). */
  online?: boolean;
  lastSeen?: number;
}

/** Persistierte Double-Ratchet-Sitzung zu einem echten Kontakt. */
export interface StoredSession {
  peerUserId: string;
  ratchet: RatchetSnapshot;
  initiator: boolean;     // true = wir haben den Handshake begonnen (Alice)
  handshakeSent: boolean; // true, sobald unser Ephemeral-Key einmal übertragen wurde
  /** Aus dem gemeinsamen Sitzungsgeheimnis abgeleitetes, unverknüpfbares
   *  Tag (siehe net/realchat.ts: deriveSessionTag) — ersetzt die Konto-ID
   *  als Routing-Hinweis bei Folgenachrichten, damit der Relay den
   *  Absender NICHT mehr in der zugestellten Nachricht sieht/speichert
   *  ("Sealed Sender", nur bei bereits bestehender Sitzung möglich). */
  tag: string;
}

/** Alles, was verschlüsselt im Vault persistiert wird. */
export interface VaultData {
  identity: Identity;
  settings: Settings;
  chats: Chat[];
  messages: Record<string, Message[]>; // chatId -> Verlauf
  secLog: SecEvent[];
  /** Demo-Modus: stabile Peer-Identitäten (damit Safety Numbers konstant bleiben) */
  demoPeerKeys: Record<string, { priv: string; pub: string; name: string }>;
  /** Echte Kontakte + persistierte 1:1-Sitzungen + Gruppen-Epoch-Keys */
  contacts: Record<string, Contact>;
  sessions: Record<string, StoredSession>;      // key = contact userId
  groupKeys: Record<string, { key: string; epoch: number }>; // key = chatId
  /** Eigene, noch unverbrauchte One-Time-Prekeys für volles X3DH (siehe
   *  net/realchat.ts) — key = Prekey-ID. Muss über Neustarts hinweg
   *  erhalten bleiben, sonst würde der Bestand beim Relay nie befüllt. */
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
