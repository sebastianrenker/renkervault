import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { b64, newEd25519, newX25519, utf8 } from '../crypto/primitives';
import { newPqKeyPair } from '../crypto/pq';
import { safetyNumber, shortFingerprint } from '../crypto/safety';
import {
  checkIntegrity, createVault, demoTamperVault, destroyVault, hasDuressPin,
  lockVault, saveVault, unlockVault, vaultExists,
} from '../crypto/vault';
import {
  buildDemoWorld, demoEncryptFile, demoPeerReply, demoRotateEpoch,
  demoSendDirect, demoSendSym, restoreDemoSessions,
} from '../demo/seed';
import { CallKind, CallSession, newCallId } from '../net/call';
import { Envelope, RelayClient, RelayStatus } from '../net/client';
import { realChat } from '../net/realchat';
import {
  AlarmState, Chat, Contact, DEFAULT_RELAY_URL, DEFAULT_SETTINGS, DeviceInfo, Identity, Member,
  MemberPermissions, Message, ReplyRef, SecEvent, Settings, ThemeName, VaultData, uid,
} from '../state/types';
import { AlarmOverlay } from './Alarm';
import { CallOverlay } from './CallOverlay';
import { ChatWindow } from './ChatWindow';
import { LockVisual } from './LockVisual';
import { ForwardModal } from './MessageModals';
import { CreateVault, UnlockVault } from './Onboarding';
import { ContactsPage, SettingsPage } from './Pages';
import { AddContactModal, CreateGroupModal } from './RealModals';
import { SecurityCenter } from './SecurityCenter';
import { SecurityPanel } from './SecurityPanel';
import { ThemeBar } from './ThemeBar';

type Phase = 'create' | 'unlock' | 'main' | 'lockdown';
type View = 'chats' | 'contacts' | 'security' | 'settings';
type Tab = 'all' | 'direct' | 'group' | 'channel' | 'archived';

export interface CallUiState {
  callId: string;
  peerId: string;
  peerName: string;
  kind: CallKind;
  direction: 'in' | 'out';
  status: 'ringing' | 'connecting' | 'connected' | 'ended';
  muted: boolean;
  cameraOff: boolean;
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  pendingOfferSdp?: RTCSessionDescriptionInit;
}

const NO_ALARM: AlarmState = { active: false, reason: '', kind: '', ts: 0, lockdown: false };

const MAX_FILE_BYTES = 1.2 * 1024 * 1024;

function ev(severity: SecEvent['severity'], kind: string, text: string, device?: string): SecEvent {
  return { id: uid('e'), ts: Date.now(), severity, kind, text, device };
}

function lastMessagePreview(messages: Message[] | undefined): string {
  if (!messages || messages.length === 0) return 'Keine Nachrichten';
  const m = messages[messages.length - 1];
  if (m.kind === 'system') return m.body;
  if (m.deleted) return '🗑 Nachricht gelöscht';
  if (m.kind === 'file') return `📎 ${m.fileName ?? 'Anhang'}`;
  return (m.own ? 'Du: ' : '') + m.body;
}

function playSiren() {
  try {
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sawtooth';
    gain.gain.value = 0.06;
    osc.connect(gain).connect(ctx.destination);
    const t0 = ctx.currentTime;
    for (let i = 0; i < 4; i++) {
      osc.frequency.setValueAtTime(620, t0 + i * 0.5);
      osc.frequency.linearRampToValueAtTime(880, t0 + i * 0.5 + 0.25);
      osc.frequency.linearRampToValueAtTime(620, t0 + i * 0.5 + 0.5);
    }
    osc.start(t0);
    osc.stop(t0 + 2);
    osc.onended = () => ctx.close();
  } catch {}
}

export default function App() {
  const [phase, setPhase] = useState<Phase>(vaultExists() ? 'unlock' : 'create');
  const [busy, setBusy] = useState(false);
  const [data, setData] = useState<VaultData | null>(null);
  const [duress, setDuress] = useState(false);
  const [alarm, setAlarm] = useState<AlarmState>(NO_ALARM);

  const [fails, setFails] = useState(0);
  const [lockedUntil, setLockedUntil] = useState(0);
  const [deviceMismatch, setDeviceMismatch] = useState(false);
  const pendingEvents = useRef<SecEvent[]>([]);

  const [relayStatus, setRelayStatus] = useState<RelayStatus>('offline');
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const relayRef = useRef<RelayClient | null>(null);

  const dataRef = useRef<VaultData | null>(null);
  useEffect(() => { dataRef.current = data; }, [data]);
  const activeChatIdRef = useRef<string | null>(null);

  const [view, setView] = useState<View>('chats');
  const [tab, setTab] = useState<Tab>('all');
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [showCt, setShowCt] = useState(false);
  const [typingFrom, setTypingFrom] = useState<string | null>(null);
  const [integrityResult, setIntegrityResult] = useState<string | null>(null);

  const [showAddContact, setShowAddContact] = useState(false);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [contactBusy, setContactBusy] = useState(false);
  const [contactError, setContactError] = useState('');
  const [groupError, setGroupError] = useState('');

  const [searchQuery, setSearchQuery] = useState('');
  const [forwardMsg, setForwardMsg] = useState<Message | null>(null);

  const [call, setCall] = useState<CallUiState | null>(null);
  const callSessionRef = useRef<CallSession | null>(null);
  const callRef = useRef<CallUiState | null>(null);
  useEffect(() => { callRef.current = call; }, [call]);

  useEffect(() => { activeChatIdRef.current = activeChatId; }, [activeChatId]);

  const settings: Settings = data?.settings ?? DEFAULT_SETTINGS;

  useEffect(() => {
    document.documentElement.dataset.theme = settings.theme;
    document.documentElement.style.setProperty('--accent', settings.accent);
  }, [settings.theme, settings.accent]);

  useEffect(() => {
    if (!data || phase !== 'main' || duress) return;
    const t = setTimeout(() => { void saveVault(data); }, 400);
    return () => clearTimeout(t);
  }, [data, phase, duress]);

  useEffect(() => {
    if (phase !== 'main') return;
    const t = setInterval(() => {
      setData((d) => {
        if (!d) return d;
        const now = Date.now();
        let changed = false;
        const messages: Record<string, Message[]> = {};
        for (const [cid, list] of Object.entries(d.messages)) {
          const kept = list.filter((m) => !m.expiresAt || m.expiresAt > now);
          if (kept.length !== list.length) changed = true;
          messages[cid] = kept;
        }
        return changed ? { ...d, messages } : d;
      });
    }, 5000);
    return () => clearInterval(t);
  }, [phase]);

  const log = useCallback((e: SecEvent) => {
    setData((d) => (d ? { ...d, secLog: [...d.secLog, e] } : d));
  }, []);

  const appendMsg = useCallback((chatId: string, m: Message) => {
    setData((d) => d ? {
      ...d,
      messages: { ...d.messages, [chatId]: [...(d.messages[chatId] ?? []), m] },
    } : d);
  }, []);

  const appendIncoming = useCallback((chatId: string, m: Message) => {
    setData((d) => {
      if (!d) return d;
      const bump = activeChatIdRef.current === chatId ? 0 : 1;
      return {
        ...d,
        messages: { ...d.messages, [chatId]: [...(d.messages[chatId] ?? []), m] },
        chats: d.chats.map((c) => (c.id === chatId ? { ...c, unread: c.unread + bump } : c)),
      };
    });
  }, []);

  const mutateMessage = useCallback((chatId: string, msgId: string, mutator: (m: Message) => Message) => {
    setData((d) => {
      if (!d) return d;
      const list = d.messages[chatId];
      if (!list) return d;
      return { ...d, messages: { ...d.messages, [chatId]: list.map((m) => (m.id === msgId ? mutator(m) : m)) } };
    });
  }, []);

  const clearPinIfMatches = useCallback((chatId: string, msgId: string) => {
    setData((d) => {
      if (!d) return d;
      const chat = d.chats.find((c) => c.id === chatId);
      if (!chat || chat.pinnedMessageId !== msgId) return d;
      return { ...d, chats: d.chats.map((c) => (c.id === chatId ? { ...c, pinnedMessageId: null } : c)) };
    });
  }, []);

  const updateContactPresence = useCallback((peerId: string, patch: { online?: boolean; lastSeen?: number }) => {
    setData((d) => {
      if (!d || !d.contacts[peerId]) return d;
      return { ...d, contacts: { ...d.contacts, [peerId]: { ...d.contacts[peerId], ...patch } } };
    });
  }, []);

  const persistRealSessions = useCallback(() => {
    setData((d) => {
      if (!d) return d;
      const prevInit: Record<string, boolean> = {};
      for (const [id, s] of Object.entries(d.sessions)) prevInit[id] = s.initiator;
      return {
        ...d,
        sessions: realChat.snapshotSessions(prevInit),
        groupKeys: realChat.snapshotGroupKeys(),
        oneTimePrekeys: realChat.snapshotOneTimePrekeys(),
      };
    });
  }, []);

  const topUpAndPublishOtpks = useCallback(() => {
    const created = realChat.topUpOneTimePrekeys();
    if (created.length > 0) persistRealSessions();
    relayRef.current?.publishOneTimePrekeys(realChat.publishableOneTimePrekeys());
  }, [persistRealSessions]);

  const triggerAlarm = useCallback((kind: string, reason: string, opts?: { lockdown?: boolean; device?: string }) => {
    setAlarm({ active: true, kind, reason, ts: Date.now(), lockdown: !!opts?.lockdown });
    const e = ev('alert', kind, `🚨 ${reason}`, opts?.device);
    if (phase === 'main') log(e); else pendingEvents.current.push(e);
    if (settings.alarmSound) playSiren();
    if (opts?.lockdown) setPhase('lockdown');
  }, [phase, log, settings.alarmSound]);

  const handleDeliver = useCallback(async (rawFrom: string | null, envelope: Envelope) => {
    const d = dataRef.current;
    if (!d) return;
    const myIdentity = d.identity;

    const from = rawFrom ?? (envelope.tag ? realChat.resolvePeerByTag(envelope.tag) : undefined);
    if (!from) {
      log(ev('warn', 'UNKNOWN_SENDER', 'Nachricht mit nicht auflösbarem Sealed-Sender-Tag verworfen'));
      return;
    }

    if (envelope.kind === 'group-key') {
      if (!realChat.hasSession(from)) {
        log(ev('warn', 'GROUP_KEY_UNKNOWN', `Gruppenschlüssel von unbekanntem Absender ${from} ignoriert`));
        return;
      }
      let plaintext: Uint8Array;
      try { plaintext = await realChat.decryptDirect(from, envelope); }
      catch { log(ev('warn', 'RATCHET_FAIL', `Gruppenschlüssel von ${from} konnte nicht entschlüsselt werden`)); return; }
      let payload: { groupId: string; groupName: string; epoch: number; key: string; members: Member[] };
      try { payload = JSON.parse(utf8.dec(plaintext)); } catch { return; }
      const fp = realChat.applyGroupKey(payload.groupId, payload.key, payload.epoch);
      setData((cur) => {
        if (!cur) return cur;
        const exists = cur.chats.find((c) => c.id === payload.groupId);
        const sub = `${payload.members.length} Mitglieder · E2E (Epoche ${payload.epoch})`;
        const chat: Chat = exists
          ? { ...exists, epoch: payload.epoch, shortFp: fp, keyRotatedAt: Date.now(), members: payload.members, sub }
          : {
              id: payload.groupId, kind: 'group', origin: 'real', name: payload.groupName, sub,
              members: payload.members, safetyNumber: '', shortFp: fp, verified: false,
              disappearSec: 0, epoch: payload.epoch, keyRotatedAt: Date.now(), unread: 1,
            };
        const chats = exists ? cur.chats.map((c) => (c.id === chat.id ? chat : c)) : [...cur.chats, chat];
        const messages = cur.messages[chat.id] ? cur.messages : { ...cur.messages, [chat.id]: [] };
        return { ...cur, chats, messages };
      });
      log(ev('info', 'KEY_ROTATION', `Gruppenschlüssel für „${payload.groupName}" empfangen (Epoche ${payload.epoch})`));
      persistRealSessions();
      return;
    }

    if (envelope.chatKind === 'direct') {
      let plaintext: Uint8Array;
      let isNew = false;
      if (realChat.hasSession(from)) {
        try { plaintext = await realChat.decryptDirect(from, envelope); }
        catch { log(ev('warn', 'RATCHET_FAIL', `Nachricht von ${from} konnte nicht entschlüsselt werden`)); return; }
      } else {
        if (!envelope.x3dh) {
          log(ev('warn', 'UNKNOWN_SENDER', `Nachricht von unbekanntem Absender ${from} ohne Handshake-Info ignoriert`));
          return;
        }
        try { plaintext = await realChat.acceptFirstMessage(myIdentity, from, envelope); }
        catch { log(ev('warn', 'HANDSHAKE_FAIL', `Handshake mit ${from} fehlgeschlagen`)); return; }
        isNew = true;
      }

      if (isNew) {
        const info = relayRef.current ? await relayRef.current.lookup(from) : null;
        const name = envelope.fromName || from;
        const contact: Contact = {
          userId: from, name, edPub: info?.edPub ?? '', xPub: info?.xPub ?? '',
          prekeyPub: info?.prekeyPub ?? '', pqPrekeyPub: info?.pqPrekeyPub ?? '',
          addedAt: Date.now(), verified: false,
          online: true, lastSeen: envelope.ts || Date.now(),
        };
        const sn = contact.xPub ? safetyNumber(b64.dec(myIdentity.xPub), b64.dec(contact.xPub)) : '';
        const fp = contact.xPub ? shortFingerprint(b64.dec(contact.xPub)) : '';
        setData((cur) => {
          if (!cur) return cur;
          const chatExists = cur.chats.some((c) => c.id === from);
          const chat: Chat = {
            id: from, kind: 'direct', origin: 'real', name, sub: 'Neue Kontaktanfrage',
            members: [
              { id: myIdentity.userId, name: myIdentity.displayName, role: 'member' },
              { id: from, name, role: 'member' },
            ],
            safetyNumber: sn, shortFp: fp, verified: false, disappearSec: 0,
            epoch: 1, keyRotatedAt: Date.now(), unread: 0,
          };
          return {
            ...cur,
            contacts: { ...cur.contacts, [from]: contact },
            chats: chatExists ? cur.chats : [...cur.chats, chat],
            messages: cur.messages[from] ? cur.messages : { ...cur.messages, [from]: [] },
          };
        });
        log(ev('warn', 'NEW_CONTACT', `Neue Kontaktanfrage von ${name} (${from})`));
      } else {
        updateContactPresence(from, { online: true, lastSeen: envelope.ts || Date.now() });
      }

      if (envelope.kind === 'text' && realChat.isCoverTraffic(plaintext)) {
        persistRealSessions();
        return;
      }

      if (envelope.kind === 'edit' && envelope.targetMsgId) {
        mutateMessage(from, envelope.targetMsgId, (m) => ({ ...m, body: utf8.dec(plaintext), edited: true }));
        persistRealSessions();
        return;
      }
      if (envelope.kind === 'delete' && envelope.targetMsgId) {
        mutateMessage(from, envelope.targetMsgId, (m) => ({ ...m, deleted: true, body: '', ct: '', fileDataUrl: undefined, reactions: undefined }));
        clearPinIfMatches(from, envelope.targetMsgId);
        persistRealSessions();
        return;
      }
      if (envelope.kind === 'reaction' && envelope.targetMsgId && envelope.emoji) {
        const emoji = envelope.emoji;
        mutateMessage(from, envelope.targetMsgId, (m) => {
          const reactions = { ...(m.reactions ?? {}) };
          const list = new Set(reactions[emoji] ?? []);
          if (envelope.reactionOp === 'remove') list.delete(from); else list.add(from);
          reactions[emoji] = [...list];
          return { ...m, reactions };
        });
        persistRealSessions();
        return;
      }
      if (envelope.kind === 'presence') {
        updateContactPresence(from, { online: envelope.presence === 'online', lastSeen: envelope.ts || Date.now() });
        persistRealSessions();
        return;
      }

      if (envelope.kind === 'call-offer' || envelope.kind === 'call-answer' ||
          envelope.kind === 'call-ice' || envelope.kind === 'call-hangup') {
        let payload: any;
        try { payload = JSON.parse(utf8.dec(plaintext)); } catch { return; }
        const active = callRef.current;

        if (envelope.kind === 'call-offer') {
          if (active && active.callId !== payload.callId) {
            const marker = utf8.enc(JSON.stringify({ callId: payload.callId }));
            void realChat.encryptDirect(from, myIdentity, marker).then((enc) => {
              relayRef.current?.sendEnvelope(from, {
                ct: enc.ct, chatId: from, chatKind: 'direct', kind: 'call-hangup',
                msgId: uid('m'), ts: Date.now(), fromName: myIdentity.displayName,
                header: enc.header, x3dh: enc.x3dh, tag: enc.tag,
              });
            });
            return;
          }
          const contactName = dataRef.current?.contacts[from]?.name || from;
          setCall({
            callId: payload.callId, peerId: from, peerName: contactName, kind: payload.kind,
            direction: 'in', status: 'ringing', muted: false, cameraOff: false,
            localStream: null, remoteStream: null, pendingOfferSdp: { type: 'offer', sdp: payload.sdp },
          });
          persistRealSessions();
          return;
        }

        if (!active || active.callId !== payload.callId) { persistRealSessions(); return; }

        if (envelope.kind === 'call-answer') {
          void callSessionRef.current?.applyAnswer({ type: 'answer', sdp: payload.sdp });
        } else if (envelope.kind === 'call-ice') {
          void callSessionRef.current?.addIceCandidate(payload.candidate);
        } else if (envelope.kind === 'call-hangup') {
          callSessionRef.current?.close();
          callSessionRef.current = null;
          setCall(null);
        }
        persistRealSessions();
        return;
      }

      const text = envelope.kind === 'file' ? '' : utf8.dec(plaintext);
      const previewable = !!envelope.fileMime && (envelope.fileMime.startsWith('image/') || envelope.fileMime.startsWith('audio/'));
      const fileDataUrl = envelope.kind === 'file' && previewable ? `data:${envelope.fileMime};base64,${b64.enc(plaintext)}` : undefined;

      appendIncoming(from, {
        id: envelope.msgId || uid('m'), from, fromName: envelope.fromName || from,
        body: text, ct: envelope.ct, ts: envelope.ts || Date.now(), own: false,
        kind: envelope.kind === 'file' ? 'file' : 'text',
        fileName: envelope.fileName, fileSize: envelope.fileSize, fileMime: envelope.fileMime, fileDataUrl,
        expiresAt: envelope.expiresAt, replyTo: envelope.replyTo, forwardedFrom: envelope.forwardedFrom,
      });
      persistRealSessions();
      return;
    }

    if (envelope.chatKind === 'group') {
      if (!envelope.chatId) return;
      let plaintext: Uint8Array;
      try { plaintext = await realChat.decryptGroup(envelope.chatId, envelope.ct); }
      catch {
        log(ev('warn', 'GROUP_DECRYPT_FAIL', `Gruppennachricht in „${envelope.chatId}" nicht entschlüsselbar (fehlender Epoch-Key?)`));
        return;
      }

      if (envelope.kind === 'edit' && envelope.targetMsgId) {
        mutateMessage(envelope.chatId, envelope.targetMsgId, (m) => ({ ...m, body: utf8.dec(plaintext), edited: true }));
        return;
      }
      if (envelope.kind === 'delete' && envelope.targetMsgId) {
        mutateMessage(envelope.chatId, envelope.targetMsgId, (m) => ({ ...m, deleted: true, body: '', ct: '', fileDataUrl: undefined, reactions: undefined }));
        clearPinIfMatches(envelope.chatId, envelope.targetMsgId);
        return;
      }
      if (envelope.kind === 'reaction' && envelope.targetMsgId && envelope.emoji) {
        const emoji = envelope.emoji;
        mutateMessage(envelope.chatId, envelope.targetMsgId, (m) => {
          const reactions = { ...(m.reactions ?? {}) };
          const list = new Set(reactions[emoji] ?? []);
          if (envelope.reactionOp === 'remove') list.delete(from); else list.add(from);
          reactions[emoji] = [...list];
          return { ...m, reactions };
        });
        return;
      }

      const previewable = !!envelope.fileMime && (envelope.fileMime.startsWith('image/') || envelope.fileMime.startsWith('audio/'));
      const fileDataUrl = envelope.kind === 'file' && previewable ? `data:${envelope.fileMime};base64,${b64.enc(plaintext)}` : undefined;

      appendIncoming(envelope.chatId, {
        id: envelope.msgId || uid('m'), from, fromName: envelope.fromName || from,
        body: envelope.kind === 'file' ? '' : utf8.dec(plaintext), ct: envelope.ct, ts: envelope.ts || Date.now(), own: false,
        kind: envelope.kind === 'file' ? 'file' : 'text', fileName: envelope.fileName, fileSize: envelope.fileSize,
        fileMime: envelope.fileMime, fileDataUrl, replyTo: envelope.replyTo, forwardedFrom: envelope.forwardedFrom,
      });
    }
  }, [log, appendIncoming, mutateMessage, clearPinIfMatches, persistRealSessions, updateContactPresence]);

  const sendCallSignal = useCallback(async (peerId: string, kind: Envelope['kind'], payload: unknown) => {
    const d = dataRef.current;
    if (!d) return;
    const enc = await realChat.encryptDirect(peerId, d.identity, utf8.enc(JSON.stringify(payload)));
    relayRef.current?.sendEnvelope(peerId, {
      ct: enc.ct, chatId: peerId, chatKind: 'direct', kind,
      msgId: uid('m'), ts: Date.now(), fromName: d.identity.displayName,
      header: enc.header, x3dh: enc.x3dh, tag: enc.tag,
    });
    persistRealSessions();
  }, [persistRealSessions]);

  const startCall = useCallback(async (peerId: string, peerName: string, kind: CallKind) => {
    if (callRef.current) return;
    const callId = newCallId();
    const session = new CallSession(callId, peerId, kind);
    callSessionRef.current = session;
    setCall({
      callId, peerId, peerName, kind, direction: 'out', status: 'connecting',
      muted: false, cameraOff: false, localStream: null, remoteStream: session.remoteStream,
    });
    session.onIceCandidate = (candidate) => { void sendCallSignal(peerId, 'call-ice', { callId, candidate }); };
    session.onConnectionStateChange = (s) => {
      if (s === 'connected') setCall((c) => (c && c.callId === callId ? { ...c, status: 'connected' } : c));
      if (s === 'failed' || s === 'closed') setCall((c) => (c && c.callId === callId ? null : c));
    };
    session.onRemoteTrack = () => { setCall((c) => (c && c.callId === callId ? { ...c, remoteStream: session.remoteStream } : c)); };
    try {
      await session.startLocalMedia();
      setCall((c) => (c && c.callId === callId ? { ...c, localStream: session.localStream } : c));
      const offer = await session.createOffer();
      await sendCallSignal(peerId, 'call-offer', { callId, kind, sdp: offer.sdp });
    } catch (e) {
      log(ev('warn', 'CALL_FAIL', `Anruf an ${peerName} fehlgeschlagen: ${e instanceof Error ? e.message : 'Medienzugriff verweigert'}`));
      session.close();
      callSessionRef.current = null;
      setCall(null);
    }
  }, [sendCallSignal, log]);

  const acceptCall = useCallback(async () => {
    const c = callRef.current;
    if (!c || !c.pendingOfferSdp || c.direction !== 'in') return;
    const session = new CallSession(c.callId, c.peerId, c.kind);
    callSessionRef.current = session;
    session.onIceCandidate = (candidate) => { void sendCallSignal(c.peerId, 'call-ice', { callId: c.callId, candidate }); };
    session.onConnectionStateChange = (s) => {
      if (s === 'connected') setCall((cur) => (cur && cur.callId === c.callId ? { ...cur, status: 'connected' } : cur));
      if (s === 'failed' || s === 'closed') setCall((cur) => (cur && cur.callId === c.callId ? null : cur));
    };
    session.onRemoteTrack = () => { setCall((cur) => (cur && cur.callId === c.callId ? { ...cur, remoteStream: session.remoteStream } : cur)); };
    try {
      await session.startLocalMedia();
      setCall((cur) => (cur && cur.callId === c.callId ? { ...cur, localStream: session.localStream, status: 'connecting' } : cur));
      const answer = await session.createAnswer(c.pendingOfferSdp);
      await sendCallSignal(c.peerId, 'call-answer', { callId: c.callId, sdp: answer.sdp });
    } catch (e) {
      log(ev('warn', 'CALL_FAIL', `Anruf konnte nicht angenommen werden: ${e instanceof Error ? e.message : 'Medienzugriff verweigert'}`));
      session.close();
      callSessionRef.current = null;
      setCall(null);
      void sendCallSignal(c.peerId, 'call-hangup', { callId: c.callId });
    }
  }, [sendCallSignal, log]);

  const hangupCall = useCallback(() => {
    const c = callRef.current;
    if (!c) return;
    callSessionRef.current?.close();
    callSessionRef.current = null;
    setCall(null);
    void sendCallSignal(c.peerId, 'call-hangup', { callId: c.callId });
  }, [sendCallSignal]);

  const toggleCallMute = useCallback(() => {
    setCall((c) => {
      if (!c) return c;
      const muted = !c.muted;
      callSessionRef.current?.setMuted(muted);
      return { ...c, muted };
    });
  }, []);

  const toggleCallCamera = useCallback(() => {
    setCall((c) => {
      if (!c) return c;
      const cameraOff = !c.cameraOff;
      callSessionRef.current?.setCameraOff(cameraOff);
      return { ...c, cameraOff };
    });
  }, []);

  const broadcastPresence = useCallback(async (state: 'online' | 'offline') => {
    const d = dataRef.current;
    if (!d) return;
    for (const peerId of Object.keys(d.contacts)) {
      if (!realChat.hasSession(peerId)) continue;
      try {
        const marker = utf8.enc('presence');
        const enc = await realChat.encryptDirect(peerId, d.identity, marker);
        relayRef.current?.sendEnvelope(peerId, {
          ct: enc.ct, chatId: peerId, chatKind: 'direct', kind: 'presence',
          msgId: uid('m'), ts: Date.now(), fromName: d.identity.displayName,
          header: enc.header, x3dh: enc.x3dh, tag: enc.tag, presence: state,
        });
      } catch {}
    }
    persistRealSessions();
  }, [persistRealSessions]);

  const sendCoverTraffic = useCallback(async () => {
    const d = dataRef.current;
    if (!d) return;
    const peers = realChat.sessionPeerIds();
    if (peers.length === 0) return;
    const peerId = peers[Math.floor(Math.random() * peers.length)];
    try {
      const enc = await realChat.encryptDirect(peerId, d.identity, realChat.coverTrafficPlaintext());
      relayRef.current?.sendEnvelope(peerId, {
        ct: enc.ct, chatId: peerId, chatKind: 'direct', kind: 'text',
        msgId: uid('m'), ts: Date.now(), fromName: d.identity.displayName,
        header: enc.header, x3dh: enc.x3dh, tag: enc.tag,
      });
      persistRealSessions();
    } catch {}
  }, [persistRealSessions]);

  useEffect(() => {
    if (phase !== 'main' || duress || relayStatus !== 'online' || !settings.coverTraffic) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const MEAN_MS = 60_000, MIN_MS = 20_000, MAX_MS = 180_000;
    const nextDelay = () => {
      const exp = -MEAN_MS * Math.log(1 - Math.random());
      return Math.min(MAX_MS, Math.max(MIN_MS, exp));
    };
    const tick = () => {
      timer = setTimeout(async () => {
        if (cancelled) return;
        await sendCoverTraffic();
        if (!cancelled) tick();
      }, nextDelay());
    };
    tick();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [phase, duress, relayStatus, settings.coverTraffic, sendCoverTraffic]);

  useEffect(() => {
    if (phase !== 'main' || !data || duress) return;
    const relay = new RelayClient({
      onStatus: (s) => {
        setRelayStatus(s);
        if (s === 'online') {
          void broadcastPresence('online');
          topUpAndPublishOtpks();
        }
      },
      onSecurityEvent: (kind, detail, _ts) => {
        if (kind === 'auth-fail') {
          log(ev('warn', 'AUTH_FAIL', `Fehlgeschlagener Anmeldeversuch (${detail.attempts ?? '?'}/5)`, String(detail.device ?? '')));
        } else if (kind === 'lockout') {
          triggerAlarm('BRUTE_FORCE', `Konto-Lockout: zu viele Fehlversuche (${detail.seconds ?? 60}s Sperre)`);
        } else if (kind === 'new-device') {
          log(ev('warn', 'NEW_DEVICE', `Neues Gerät „${detail.name ?? detail.deviceId}" wartet auf manuelle Bestätigung`, String(detail.name ?? '')));
        } else if (kind === 'key-mismatch') {
          triggerAlarm('KEY_MISMATCH', 'Gerät meldet sich mit ANDEREM Schlüssel — möglicher Angriff');
        } else if (kind === 'device-approved') {
          log(ev('info', 'DEVICE_OK', `Gerät bestätigt: ${detail.name ?? detail.deviceId}`));
        } else if (kind === 'device-revoked') {
          log(ev('info', 'DEVICE_REVOKED', `Gerät abgemeldet: ${detail.deviceId}`));
        }
      },
      onDevices: (list) =>
        setDevices(list.map((d) => ({
          id: d.deviceId, name: d.name, trusted: d.trusted, online: d.online,
          current: d.current, createdAt: d.createdAt, lastSeen: d.lastSeen,
        }))),
      onRevoked: () => {
        triggerAlarm('SESSION_REVOKED', 'Diese Sitzung wurde remote abgemeldet', { lockdown: true });
      },
      onDeliver: (from, envelope) => { void handleDeliver(from, envelope); },
    });
    relayRef.current = relay;
    relay.connect(data.identity, data.settings.relayUrl || DEFAULT_RELAY_URL);
    return () => {
      void broadcastPresence('offline');
      relay.disconnect();
      relayRef.current = null;
    };
  }, [phase, duress, data?.settings.relayUrl]);

  const handleCreate = async (opts: {
    displayName: string; userId: string; passphrase: string; duressPin: string | null;
  }) => {
    setBusy(true);
    try {
      const x = newX25519();
      const e = newEd25519();
      const prekey = newX25519();
      const pqPrekey = newPqKeyPair();
      const identity: Identity = {
        userId: opts.userId, displayName: opts.displayName,
        xPriv: b64.enc(x.priv), xPub: b64.enc(x.pub),
        edPriv: b64.enc(e.priv), edPub: b64.enc(e.pub),
        prekeyPriv: b64.enc(prekey.priv), prekeyPub: b64.enc(prekey.pub),
        pqPrekeyPriv: b64.enc(pqPrekey.secretKey), pqPrekeyPub: b64.enc(pqPrekey.publicKey),
        deviceId: uid('dev-'), deviceName: 'Desktop (dieses Gerät)',
      };
      realChat.hydrate({}, {});
      realChat.topUpOneTimePrekeys();
      const world = await buildDemoWorld(identity);
      const vault: VaultData = {
        identity, settings: { ...DEFAULT_SETTINGS },
        chats: world.chats, messages: world.messages,
        secLog: [...world.secLog, ev('info', 'VAULT_UNLOCKED', 'Tresor erstellt und entsperrt')],
        demoPeerKeys: world.peerKeys,
        contacts: {}, sessions: {}, groupKeys: {},
        oneTimePrekeys: realChat.snapshotOneTimePrekeys(),
      };
      await createVault(opts.passphrase, opts.duressPin, vault);
      setData(vault);
      setDuress(false);
      setPhase('main');
    } finally {
      setBusy(false);
    }
  };

  const handleUnlock = async (passphrase: string) => {
    if (lockedUntil > Date.now()) return;
    setBusy(true);
    setDeviceMismatch(false);
    try {
      const res = await unlockVault<VaultData>(passphrase);
      if (res.ok && res.duress) {
        const fakeIdentity: Identity = {
          userId: 'RV-0000-0000', displayName: 'Operator',
          xPriv: '', xPub: '', edPriv: '', edPub: '', prekeyPriv: '', prekeyPub: '',
          pqPrekeyPriv: '', pqPrekeyPub: '',
          deviceId: 'dev-0', deviceName: 'Desktop',
        };
        realChat.hydrate({}, {});
        setData({
          identity: fakeIdentity, settings: { ...DEFAULT_SETTINGS },
          chats: [], messages: {},
          secLog: [ev('info', 'SESSION', 'Sitzung gestartet')],
          demoPeerKeys: {}, contacts: {}, sessions: {}, groupKeys: {}, oneTimePrekeys: {},
        });
        setDuress(true);
        setFails(0);
        setPhase('main');
        return;
      }
      if (res.ok) {
        const symChats = res.data.chats.filter((c) => c.kind !== 'direct' && c.origin === 'demo');
        const rotated = await restoreDemoSessions(
          res.data.identity, res.data.demoPeerKeys ?? {},
          symChats.map((c) => ({ id: c.id, epoch: c.epoch }))
        );
        realChat.hydrate(res.data.sessions ?? {}, res.data.groupKeys ?? {}, res.data.oneTimePrekeys ?? {});
        const chats = res.data.chats.map((c) =>
          rotated[c.id]
            ? { ...c, epoch: rotated[c.id].epoch, shortFp: rotated[c.id].fp, keyRotatedAt: Date.now() }
            : c
        );
        const merged: VaultData = {
          ...res.data, chats,
          contacts: res.data.contacts ?? {}, sessions: res.data.sessions ?? {}, groupKeys: res.data.groupKeys ?? {},
          oneTimePrekeys: res.data.oneTimePrekeys ?? {},
          secLog: [
            ...res.data.secLog, ...pendingEvents.current,
            ev('info', 'VAULT_UNLOCKED', 'Tresor entsperrt — Integrität OK'),
            ev('info', 'KEY_ROTATION', 'Demo-Sitzungsschlüssel neu etabliert (echte Kontakte/Gruppen unverändert fortgesetzt)'),
          ],
        };
        pendingEvents.current = [];
        setData(merged);
        setDuress(false);
        setFails(0);
        setPhase('main');
        return;
      }
      if (res.reason === 'tampered') {
        triggerAlarm('TAMPER', 'Integritätsprüfung fehlgeschlagen — lokale Datenbank wurde manipuliert', { lockdown: true });
        return;
      }
      if (res.reason === 'device-mismatch') {
        setDeviceMismatch(true);
        pendingEvents.current.push(ev('warn', 'DEVICE_MISMATCH', 'Tresor ist an dieses Gerät/Windows-Konto gebunden (DPAPI) — auf einem anderen Gerät nicht entsperrbar, auch mit korrekter Passphrase.'));
        return;
      }
      const n = fails + 1;
      setFails(n);
      pendingEvents.current.push(ev('warn', 'AUTH_FAIL', `Fehlgeschlagener Entsperrversuch (${n}/5)`, 'Desktop (dieses Gerät)'));
      relayRef.current?.reportUnlockFail('Desktop (dieses Gerät)');
      if (n >= 5) {
        setLockedUntil(Date.now() + 60_000);
        setFails(0);
        triggerAlarm('BRUTE_FORCE', '5 fehlgeschlagene Anmeldeversuche — Lockout 60 s aktiv', { device: 'Desktop (dieses Gerät)' });
      }
    } finally {
      setBusy(false);
    }
  };

  const handleAddContact = async (userIdInput: string, nameInput: string) => {
    if (!data) return;
    const targetId = userIdInput.trim().toUpperCase();
    if (!/^RV-[0-9A-F]{4}-[0-9A-F]{4}$/.test(targetId)) {
      setContactError('Ungültiges Format. Erwartet: RV-XXXX-XXXX'); return;
    }
    if (targetId === data.identity.userId) { setContactError('Das ist deine eigene Konto-ID.'); return; }
    if (data.contacts[targetId]) { setContactError('Dieser Kontakt existiert bereits.'); return; }
    if (!relayRef.current || relayStatus !== 'online') {
      setContactError('Relay ist offline — Kontakt-Lookup benötigt eine aktive Verbindung.'); return;
    }
    setContactBusy(true);
    setContactError('');
    try {
      const res = await relayRef.current.lookup(targetId, true);
      if (!res.found || !res.xPub || !res.prekeyPub || !res.pqPrekeyPub) {
        setContactError('Konto nicht gefunden. War die Person schon einmal mit RenkerVault online?');
        return;
      }
      const name = nameInput || targetId;
      const contact: Contact = {
        userId: targetId, name, edPub: res.edPub ?? '', xPub: res.xPub, prekeyPub: res.prekeyPub,
        pqPrekeyPub: res.pqPrekeyPub, addedAt: Date.now(), verified: false,
      };
      realChat.beginSession(data.identity, contact, res.otpk ?? undefined);
      const sn = safetyNumber(b64.dec(data.identity.xPub), b64.dec(contact.xPub));
      const fp = shortFingerprint(b64.dec(contact.xPub));
      const chat: Chat = {
        id: targetId, kind: 'direct', origin: 'real', name, sub: 'Neuer Kontakt · noch keine Nachrichten',
        members: [
          { id: data.identity.userId, name: data.identity.displayName, role: 'member' },
          { id: targetId, name, role: 'member' },
        ],
        safetyNumber: sn, shortFp: fp, verified: false, disappearSec: 0,
        epoch: 1, keyRotatedAt: Date.now(), unread: 0,
      };
      setData((d) => d ? {
        ...d,
        contacts: { ...d.contacts, [targetId]: contact },
        chats: [...d.chats, chat],
        messages: { ...d.messages, [targetId]: [] },
      } : d);
      persistRealSessions();
      log(ev('info', 'CONTACT_ADDED', `Echter Kontakt hinzugefügt: ${name} (${targetId}) — Sitzung etabliert`));
      setShowAddContact(false);
      setView('chats'); setTab('direct'); setActiveChatId(targetId);
    } finally {
      setContactBusy(false);
    }
  };

  const distributeGroupKey = (chatId: string, groupName: string, epoch: number, members: Member[]) => {
    if (!data) return;
    const cur = realChat.currentGroupKeyB64(chatId);
    if (!cur) return;
    const payloadBytes = utf8.enc(JSON.stringify({ groupId: chatId, groupName, epoch, key: cur.key, members }));
    members.forEach(async (m) => {
      if (m.id === data.identity.userId) return;
      if (!realChat.hasSession(m.id)) {
        log(ev('warn', 'GROUP_KEY_UNDELIVERED', `„${groupName}": kein Schlüssel-Kanal zu ${m.name} — erst als Kontakt hinzufügen`));
        return;
      }
      const enc = await realChat.encryptDirect(m.id, data.identity, payloadBytes);
      relayRef.current?.sendEnvelope(m.id, {
        ct: enc.ct, chatId, chatKind: 'direct', kind: 'group-key',
        msgId: uid('m'), ts: Date.now(), fromName: data.identity.displayName,
        header: enc.header, x3dh: enc.x3dh, tag: enc.tag,
      });
    });
    persistRealSessions();
  };

  const handleCreateGroup = (name: string, memberIds: string[]) => {
    if (!data) return;
    if (memberIds.length === 0) { setGroupError('Mindestens ein Mitglied einladen.'); return; }
    setGroupError('');
    const groupId = uid('grp-');
    const r = realChat.newGroupEpoch(groupId, 0);
    const members: Member[] = [
      { id: data.identity.userId, name: data.identity.displayName, role: 'owner' },
      ...memberIds.map((id) => ({ id, name: data.contacts[id]?.name ?? id, role: 'member' as const })),
    ];
    const sub = `${members.length} Mitglieder · E2E (Epoche ${r.epoch})`;
    const chat: Chat = {
      id: groupId, kind: 'group', origin: 'real', name, sub, members,
      safetyNumber: '', shortFp: r.fp, verified: false, disappearSec: 0,
      epoch: r.epoch, keyRotatedAt: Date.now(), unread: 0,
    };
    setData((d) => d ? { ...d, chats: [...d.chats, chat], messages: { ...d.messages, [groupId]: [] } } : d);
    distributeGroupKey(groupId, name, r.epoch, members);
    log(ev('info', 'GROUP_CREATED', `Echte Gruppe „${name}" erstellt (Epoche ${r.epoch}), Schlüssel an ${memberIds.length} Mitglied(er) verteilt`));
    setShowCreateGroup(false);
    setView('chats'); setTab('group'); setActiveChatId(groupId);
  };

  const rotateRealGroup = (chatId: string, members: Member[], reasonText: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    if (!chat) return;
    const r = realChat.newGroupEpoch(chatId, chat.epoch);
    const sub = `${members.length} Mitglieder · E2E (Epoche ${r.epoch})`;
    updateChat(chatId, { epoch: r.epoch, shortFp: r.fp, keyRotatedAt: Date.now(), members, sub });
    appendMsg(chatId, {
      id: uid('s'), from: 'system', fromName: 'System',
      body: `${reasonText} · Schlüssel neu verteilt (Epoche ${r.epoch})`,
      ct: '', ts: Date.now(), own: false, kind: 'system',
    });
    log(ev('info', 'KEY_ROTATION', `„${chat.name}": ${reasonText} → Epoche ${r.epoch}`));
    distributeGroupKey(chatId, chat.name, r.epoch, members);
  };

  const handleAddMemberReal = (chatId: string, contactId: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    const contact = data.contacts[contactId];
    if (!chat || !contact) return;
    const members = [...chat.members, { id: contactId, name: contact.name, role: 'member' as const }];
    rotateRealGroup(chatId, members, `${contact.name} hinzugefügt`);
  };

  const handleRemoveMemberReal = (chatId: string, memberId: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    if (!chat) return;
    const removedName = chat.members.find((m) => m.id === memberId)?.name ?? memberId;
    const members = chat.members.filter((m) => m.id !== memberId);
    rotateRealGroup(chatId, members, `${removedName} entfernt`);
  };

  const canPostIn = (chat: Chat): boolean => {
    if (chat.kind !== 'channel' || !data) return true;
    const role = chat.members.find((m) => m.id === data.identity.userId)?.role ?? 'member';
    return role === 'owner' || role === 'admin';
  };

  const handleSend = async (chatId: string, text: string, replyTo?: ReplyRef, forwardedFrom?: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    if (!chat) return;
    if (!canPostIn(chat)) {
      log(ev('warn', 'PERMISSION_DENIED', `Senden in „${chat.name}" verweigert — nur Owner/Admins dürfen in Broadcast-Kanälen posten`));
      return;
    }

    if (chat.origin === 'real') {
      const msgId = uid('m');
      const ts = Date.now();
      if (chat.kind === 'direct') {
        const enc = await realChat.encryptDirect(chatId, data.identity, utf8.enc(text));
        const expiresAt = chat.disappearSec ? ts + chat.disappearSec * 1000 : undefined;
        relayRef.current?.sendEnvelope(chatId, {
          ct: enc.ct, chatId, chatKind: 'direct', kind: 'text', msgId, ts,
          fromName: data.identity.displayName, header: enc.header, x3dh: enc.x3dh, tag: enc.tag, expiresAt,
          replyTo, forwardedFrom,
        });
        appendMsg(chatId, {
          id: msgId, from: data.identity.userId, fromName: data.identity.displayName,
          body: text, ct: enc.ct, ts, own: true, kind: 'text', expiresAt, replyTo, forwardedFrom,
        });
        persistRealSessions();
      } else if (chat.kind === 'group') {
        const enc = await realChat.encryptGroup(chatId, utf8.enc(text));
        const envelope: Envelope = {
          ct: enc.ct, chatId, chatKind: 'group', kind: 'text', msgId, ts,
          fromName: data.identity.displayName, epoch: enc.epoch, replyTo, forwardedFrom,
        };
        chat.members.forEach((m) => { if (m.id !== data.identity.userId) relayRef.current?.sendEnvelope(m.id, envelope); });
        appendMsg(chatId, {
          id: msgId, from: data.identity.userId, fromName: data.identity.displayName,
          body: text, ct: enc.ct, ts, own: true, kind: 'text', replyTo, forwardedFrom,
        });
      }
      return;
    }

    const enc = chat.kind === 'direct'
      ? await demoSendDirect(chatId, text)
      : await demoSendSym(chatId, text);
    const msg: Message = {
      id: uid('m'), from: data.identity.userId, fromName: data.identity.displayName,
      body: text, ct: enc.ct, ts: Date.now(), own: true, kind: 'text',
      expiresAt: chat.disappearSec ? Date.now() + chat.disappearSec * 1000 : undefined,
      replyTo, forwardedFrom,
    };
    appendMsg(chatId, msg);

    if (chat.kind === 'direct') {
      if (settings.typingIndicator) setTimeout(() => setTypingFrom(chat.name), 900);
      setTimeout(async () => {
        setTypingFrom(null);
        const reply = await demoPeerReply(chatId);
        if (!reply) return;
        appendMsg(chatId, {
          id: uid('m'), from: chatId, fromName: chat.name, body: reply.text, ct: reply.ct,
          ts: Date.now(), own: false, kind: 'text',
          expiresAt: chat.disappearSec ? Date.now() + chat.disappearSec * 1000 : undefined,
        });
        if (settings.readReceipts) {
          setData((d) => d ? {
            ...d,
            messages: {
              ...d.messages,
              [chatId]: d.messages[chatId].map((m) => (m.own ? { ...m, readByPeer: true } : m)),
            },
          } : d);
        }
      }, 1800 + Math.random() * 1500);
    } else if (chat.kind === 'group') {
      const responder = chat.members.find((m) => m.id !== data.identity.userId);
      if (responder) {
        setTimeout(async () => {
          const replyText = 'Angekommen — Fingerprint der Epoche stimmt bei mir. ✔';
          const rEnc = await demoSendSym(chatId, replyText);
          appendMsg(chatId, {
            id: uid('m'), from: responder.id, fromName: responder.name, body: replyText,
            ct: rEnc.ct, ts: Date.now(), own: false, kind: 'text',
          });
        }, 2200);
      }
    }
  };

  const handleFile = async (chatId: string, file: File, forwardedFrom?: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    if (!chat) return;
    if (!canPostIn(chat)) {
      log(ev('warn', 'PERMISSION_DENIED', `Senden in „${chat.name}" verweigert — nur Owner/Admins dürfen in Broadcast-Kanälen posten`));
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      log(ev('warn', 'ATTACH', `Anhang zu groß (max. ${Math.round(MAX_FILE_BYTES / 1024)} KB im Prototyp): ${file.name}`));
      return;
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    const mime = file.type || 'application/octet-stream';
    const previewable = mime.startsWith('image/') || mime.startsWith('audio/');
    const fileDataUrl = previewable ? `data:${mime};base64,${b64.enc(bytes)}` : undefined;

    if (chat.origin === 'real') {
      const msgId = uid('m'); const ts = Date.now();
      if (chat.kind === 'direct') {
        const enc = await realChat.encryptDirect(chatId, data.identity, bytes);
        relayRef.current?.sendEnvelope(chatId, {
          ct: enc.ct, chatId, chatKind: 'direct', kind: 'file', msgId, ts,
          fromName: data.identity.displayName, header: enc.header, x3dh: enc.x3dh, tag: enc.tag,
          fileName: file.name, fileSize: file.size, fileMime: mime, forwardedFrom,
        });
        persistRealSessions();
      } else {
        const enc = await realChat.encryptGroup(chatId, bytes);
        const envelope: Envelope = {
          ct: enc.ct, chatId, chatKind: 'group', kind: 'file', msgId, ts,
          fromName: data.identity.displayName, epoch: enc.epoch, fileName: file.name, fileSize: file.size,
          fileMime: mime, forwardedFrom,
        };
        chat.members.forEach((m) => { if (m.id !== data.identity.userId) relayRef.current?.sendEnvelope(m.id, envelope); });
      }
      appendMsg(chatId, {
        id: msgId, from: data.identity.userId, fromName: data.identity.displayName,
        body: '', ct: '', ts, own: true, kind: 'file', fileName: file.name, fileSize: file.size,
        fileMime: mime, fileDataUrl, forwardedFrom,
      });
      log(ev('info', 'ATTACH', `Anhang Ende-zu-Ende-verschlüsselt gesendet: ${file.name}`));
      return;
    }

    const enc = await demoEncryptFile(chatId, chat.kind === 'direct' ? 'direct' : 'sym', bytes);
    appendMsg(chatId, {
      id: uid('m'), from: data.identity.userId, fromName: data.identity.displayName,
      body: '', ct: enc.ct, ts: Date.now(), own: true, kind: 'file',
      fileName: file.name, fileSize: file.size, fileMime: mime, fileDataUrl, forwardedFrom,
    });
    log(ev('info', 'ATTACH', `Anhang Ende-zu-Ende-verschlüsselt gesendet: ${file.name}`));
  };

  const handleEditMessage = async (chatId: string, msgId: string, newText: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    if (!chat) return;
    mutateMessage(chatId, msgId, (m) => ({ ...m, body: newText, edited: true }));
    if (chat.origin !== 'real') return;
    const ts = Date.now();
    if (chat.kind === 'direct') {
      const enc = await realChat.encryptDirect(chatId, data.identity, utf8.enc(newText));
      relayRef.current?.sendEnvelope(chatId, {
        ct: enc.ct, chatId, chatKind: 'direct', kind: 'edit', msgId: uid('m'), targetMsgId: msgId, ts,
        fromName: data.identity.displayName, header: enc.header, x3dh: enc.x3dh, tag: enc.tag,
      });
      persistRealSessions();
    } else if (chat.kind === 'group') {
      const enc = await realChat.encryptGroup(chatId, utf8.enc(newText));
      const envelope: Envelope = {
        ct: enc.ct, chatId, chatKind: 'group', kind: 'edit', msgId: uid('m'), targetMsgId: msgId, ts,
        fromName: data.identity.displayName, epoch: enc.epoch,
      };
      chat.members.forEach((m) => { if (m.id !== data.identity.userId) relayRef.current?.sendEnvelope(m.id, envelope); });
    }
  };

  const handleDeleteMessage = async (chatId: string, msgId: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    if (!chat) return;
    mutateMessage(chatId, msgId, (m) => ({ ...m, deleted: true, body: '', ct: '', fileDataUrl: undefined, reactions: undefined }));
    clearPinIfMatches(chatId, msgId);
    if (chat.origin !== 'real') return;
    const ts = Date.now();
    const marker = utf8.enc('deleted');
    if (chat.kind === 'direct') {
      const enc = await realChat.encryptDirect(chatId, data.identity, marker);
      relayRef.current?.sendEnvelope(chatId, {
        ct: enc.ct, chatId, chatKind: 'direct', kind: 'delete', msgId: uid('m'), targetMsgId: msgId, ts,
        fromName: data.identity.displayName, header: enc.header, x3dh: enc.x3dh, tag: enc.tag,
      });
      persistRealSessions();
    } else if (chat.kind === 'group') {
      const enc = await realChat.encryptGroup(chatId, marker);
      const envelope: Envelope = {
        ct: enc.ct, chatId, chatKind: 'group', kind: 'delete', msgId: uid('m'), targetMsgId: msgId, ts,
        fromName: data.identity.displayName, epoch: enc.epoch,
      };
      chat.members.forEach((m) => { if (m.id !== data.identity.userId) relayRef.current?.sendEnvelope(m.id, envelope); });
    }
  };

  const handleReact = async (chatId: string, msgId: string, emoji: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    if (!chat) return;
    const myId = data.identity.userId;
    const msg = data.messages[chatId]?.find((m) => m.id === msgId);
    const already = msg?.reactions?.[emoji]?.includes(myId) ?? false;
    const op: 'add' | 'remove' = already ? 'remove' : 'add';
    mutateMessage(chatId, msgId, (m) => {
      const reactions = { ...(m.reactions ?? {}) };
      const list = new Set(reactions[emoji] ?? []);
      if (op === 'add') list.add(myId); else list.delete(myId);
      reactions[emoji] = [...list];
      return { ...m, reactions };
    });
    if (chat.origin !== 'real') return;
    const ts = Date.now();
    const marker = utf8.enc('reaction');
    if (chat.kind === 'direct') {
      const enc = await realChat.encryptDirect(chatId, data.identity, marker);
      relayRef.current?.sendEnvelope(chatId, {
        ct: enc.ct, chatId, chatKind: 'direct', kind: 'reaction', msgId: uid('m'), targetMsgId: msgId,
        emoji, reactionOp: op, ts, fromName: data.identity.displayName, header: enc.header, x3dh: enc.x3dh, tag: enc.tag,
      });
      persistRealSessions();
    } else if (chat.kind === 'group') {
      const enc = await realChat.encryptGroup(chatId, marker);
      const envelope: Envelope = {
        ct: enc.ct, chatId, chatKind: 'group', kind: 'reaction', msgId: uid('m'), targetMsgId: msgId,
        emoji, reactionOp: op, ts, fromName: data.identity.displayName, epoch: enc.epoch,
      };
      chat.members.forEach((m) => { if (m.id !== data.identity.userId) relayRef.current?.sendEnvelope(m.id, envelope); });
    }
  };

  const doForward = async (targetChatId: string) => {
    const m = forwardMsg;
    setForwardMsg(null);
    if (!m || !data || m.deleted) return;
    if (m.kind === 'file') {
      if (!m.fileDataUrl) {
        log(ev('warn', 'FORWARD_FAIL', `„${m.fileName ?? 'Anhang'}" kann nicht weitergeleitet werden — nur Bild-/Audio-Anhänge werden dafür lokal vorgehalten`));
        return;
      }
      try {
        const res = await fetch(m.fileDataUrl);
        const blob = await res.blob();
        const file = new File([blob], m.fileName ?? 'datei', { type: m.fileMime ?? blob.type });
        await handleFile(targetChatId, file, m.fromName);
      } catch {
        log(ev('warn', 'FORWARD_FAIL', 'Weiterleiten der Datei fehlgeschlagen'));
      }
      return;
    }
    await handleSend(targetChatId, m.body, undefined, m.fromName);
  };

  const handlePinMessage = (chatId: string, msgId: string | null) => {
    updateChat(chatId, { pinnedMessageId: msgId });
  };

  const handleBurnChat = (chatId: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    if (!chat) return;
    const dropContact = chat.kind === 'direct' && chat.origin === 'real';

    if (dropContact) realChat.dropSession(chatId);

    setData((d) => {
      if (!d) return d;
      const messages = { ...d.messages };
      delete messages[chatId];
      const chats = d.chats.filter((c) => c.id !== chatId);
      if (!dropContact) return { ...d, chats, messages };
      const contacts = { ...d.contacts };
      delete contacts[chatId];
      const sessions = { ...d.sessions };
      delete sessions[chatId];
      return { ...d, chats, messages, contacts, sessions };
    });
    setActiveChatId(null);
    log(ev('warn', 'CHAT_BURNED',
      `„${chat.name}" verbrannt — Verlauf${dropContact ? ' und Verschlüsselungssitzung' : ''} unwiderruflich gelöscht`));
  };

  const toggleChatFlag = (chatId: string, flag: 'pinned' | 'muted' | 'archived') => {
    const chat = data?.chats.find((c) => c.id === chatId);
    if (!chat) return;
    updateChat(chatId, { [flag]: !chat[flag] } as Partial<Chat>);
  };

  const handleSetPermission = (chatId: string, memberId: string, patch: Partial<MemberPermissions>) => {
    setData((d) => {
      if (!d) return d;
      return {
        ...d,
        chats: d.chats.map((c) => c.id !== chatId ? c : {
          ...c,
          members: c.members.map((m) => m.id !== memberId ? m : {
            ...m,
            permissions: {
              canPost: true, canInvite: true, canRemove: true, canPin: true,
              ...m.permissions, ...patch,
            },
          }),
        }),
      };
    });
  };

  const updateChat = (chatId: string, patch: Partial<Chat>) => {
    setData((d) => d ? {
      ...d, chats: d.chats.map((c) => (c.id === chatId ? { ...c, ...patch } : c)),
    } : d);
  };

  const rotateChat = (chatId: string, reasonText: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    if (!chat || chat.kind === 'direct') return;
    const r = demoRotateEpoch(chatId);
    updateChat(chatId, { epoch: r.epoch, shortFp: r.fp, keyRotatedAt: Date.now() });
    appendMsg(chatId, {
      id: uid('s'), from: 'system', fromName: 'System',
      body: `${reasonText} · Schlüssel neu verteilt (Epoche ${r.epoch})`,
      ct: '', ts: Date.now(), own: false, kind: 'system',
    });
    log(ev('info', 'KEY_ROTATION', `„${chat.name}": ${reasonText} → Epoche ${r.epoch}`));
  };

  const handleAddMember = (chatId: string, memberId: string) => {
    if (!data) return;
    const name = data.demoPeerKeys[memberId]?.name ?? memberId;
    setData((d) => d ? {
      ...d,
      chats: d.chats.map((c) => c.id === chatId
        ? { ...c, members: [...c.members, { id: memberId, name, role: 'member' as const }] }
        : c),
    } : d);
    rotateChat(chatId, `${name} hinzugefügt`);
  };

  const handleRemoveMember = (chatId: string, memberId: string) => {
    if (!data) return;
    const chat = data.chats.find((c) => c.id === chatId);
    const name = chat?.members.find((m) => m.id === memberId)?.name ?? memberId;
    setData((d) => d ? {
      ...d,
      chats: d.chats.map((c) => c.id === chatId
        ? { ...c, members: c.members.filter((m) => m.id !== memberId) }
        : c),
    } : d);
    rotateChat(chatId, `${name} entfernt`);
  };

  const rotateChatAny = (chatId: string, reasonText: string) => {
    const chat = data?.chats.find((c) => c.id === chatId);
    if (!chat) return;
    if (chat.origin === 'real') rotateRealGroup(chatId, chat.members, reasonText);
    else rotateChat(chatId, reasonText);
  };
  const addMemberAny = (chatId: string, id: string) => {
    const chat = data?.chats.find((c) => c.id === chatId);
    if (!chat) return;
    if (chat.origin === 'real') handleAddMemberReal(chatId, id);
    else handleAddMember(chatId, id);
  };
  const removeMemberAny = (chatId: string, id: string) => {
    const chat = data?.chats.find((c) => c.id === chatId);
    if (!chat) return;
    if (chat.origin === 'real') handleRemoveMemberReal(chatId, id);
    else handleRemoveMember(chatId, id);
  };

  const runIntegrityCheck = () => {
    const r = checkIntegrity();
    const label = r === 'ok' ? 'OK' : r === 'tampered' ? 'MANIPULIERT' : r.toUpperCase();
    setIntegrityResult(label);
    if (r === 'tampered') {
      triggerAlarm('TAMPER', 'HMAC-Prüfung fehlgeschlagen — lokale Datenbank wurde manipuliert',
        { lockdown: settings.autoLockdown });
    } else {
      log(ev('info', 'VAULT_CHECK', `Integritätsprüfung der lokalen Datenbank: ${label}`));
    }
  };

  const simIntrusion = () => {
    log(ev('warn', 'AUTH_FAIL', 'Fehlgeschlagener Anmeldeversuch (5/5) — Simulation', 'Unbekanntes Gerät'));
    triggerAlarm('BRUTE_FORCE', 'Simulation: 5 fehlgeschlagene Login-Versuche in 90 s — Lockout aktiv',
      { device: 'Unbekanntes Gerät' });
  };

  const simTamper = () => {
    demoTamperVault();
    log(ev('warn', 'TAMPER_SIM', 'Dev-Simulation: Byte im Vault-Ciphertext manipuliert'));
    runIntegrityCheck();
  };

  const ackAlarm = () => {
    setAlarm(NO_ALARM);
    log(ev('info', 'ALARM_ACK', 'Alarm quittiert durch Nutzer'));
  };

  const lockNow = async () => {
    callSessionRef.current?.close();
    callSessionRef.current = null;
    setCall(null);
    if (data && !duress) await saveVault(data);
    lockVault();
    realChat.hydrate({}, {});
    setAlarm(NO_ALARM);
    setData(null);
    setDuress(false);
    setActiveChatId(null);
    setView('chats');
    setPhase('unlock');
  };

  const repairVault = async () => {
    if (!data) { setPhase('unlock'); setAlarm(NO_ALARM); return; }
    await saveVault(data);
    setIntegrityResult('OK');
    setAlarm(NO_ALARM);
    log(ev('info', 'VAULT_REPAIR', 'Vault aus intaktem Sitzungszustand neu versiegelt — Integrität wiederhergestellt'));
    setPhase('main');
  };

  const destroyAll = () => {
    destroyVault();
    realChat.hydrate({}, {});
    pendingEvents.current = [];
    setData(null); setDuress(false); setAlarm(NO_ALARM);
    setFails(0); setLockedUntil(0);
    setActiveChatId(null); setView('chats');
    setPhase('create');
  };

  const chats = data?.chats ?? [];
  const filteredChats = useMemo(() => {
    let list = chats.filter((c) => (tab === 'archived' ? !!c.archived : !c.archived));
    if (tab !== 'all' && tab !== 'archived') list = list.filter((c) => c.kind === tab);
    const q = searchQuery.trim().toLowerCase();
    if (q) {
      list = list.filter((c) =>
        c.name.toLowerCase().includes(q) ||
        (data?.messages[c.id] ?? []).some((m) => !m.deleted && m.body.toLowerCase().includes(q))
      );
    }
    return [...list].sort((a, b) => {
      if (!!a.pinned !== !!b.pinned) return a.pinned ? -1 : 1;
      const la = data?.messages[a.id]?.at(-1)?.ts ?? a.keyRotatedAt;
      const lb = data?.messages[b.id]?.at(-1)?.ts ?? b.keyRotatedAt;
      return lb - la;
    });
  }, [chats, tab, searchQuery, data?.messages]);
  const activeChat = chats.find((c) => c.id === activeChatId) ?? null;
  const demoContacts = Object.entries(data?.demoPeerKeys ?? {}).map(([id, k]) => ({ id, name: k.name }));
  const realContactsList = Object.values(data?.contacts ?? {});
  const allContactsForActive = activeChat?.origin === 'real'
    ? realContactsList.map((c) => ({ id: c.userId, name: c.name }))
    : demoContacts;
  const unreadTotal = chats.reduce((n, c) => n + c.unread, 0);
  const localDevice: DeviceInfo[] = data ? [{
    id: data.identity.deviceId, name: data.identity.deviceName, trusted: true,
    online: true, current: true, createdAt: Date.now(), lastSeen: Date.now(),
  }] : [];
  const deviceList = devices.length ? devices : localDevice;
  const lastRotation = chats.reduce((t, c) => Math.max(t, c.keyRotatedAt), 0) || Date.now();

  if (phase === 'create') return <CreateVault onCreate={handleCreate} busy={busy} />;

  if (phase === 'unlock') {
    return (
      <>
        <UnlockVault
          onUnlock={handleUnlock} busy={busy} fails={fails}
          lockedUntil={lockedUntil} alarm={alarm.active} onReset={destroyAll}
          deviceMismatch={deviceMismatch}
        />
        <AlarmOverlay alarm={alarm} onAck={ackAlarm} onLock={() => setAlarm(NO_ALARM)} />
      </>
    );
  }

  if (phase === 'lockdown') {
    return (
      <div className="lockdown">
        <div className="alarm-vignette" />
        <div className="lockdown-card panel">
          <div className="big">🚨</div>
          <h1>SICHERHEITSWARNUNG — AUTO-LOCKDOWN</h1>
          <p>
            {alarm.reason || 'Manipulation der lokalen Datenbank erkannt.'}<br />
            Die App wurde gesperrt, um deine Daten zu schützen. Prüfe Gerät und
            Umgebung, bevor du fortfährst.
          </p>
          {data ? (
            <button className="btn solid" onClick={repairVault}>
              Vault aus intakter Sitzung wiederherstellen & fortfahren
            </button>
          ) : (
            <button className="btn dangerous" onClick={destroyAll}>
              Tresor unwiderruflich löschen & neu beginnen
            </button>
          )}
          <button className="btn ghost" onClick={lockNow}>Sperren & zur Anmeldung</button>
        </div>
      </div>
    );
  }

  const nav: { id: View; ico: string; label: string; tab?: Tab }[] = [
    { id: 'chats', ico: '💬', label: 'Chats', tab: 'direct' },
    { id: 'chats', ico: '⬡', label: 'Gruppen', tab: 'group' },
    { id: 'chats', ico: '📡', label: 'Kanäle', tab: 'channel' },
    { id: 'contacts', ico: '◉', label: 'Kontakte' },
    { id: 'security', ico: '⛨', label: 'Sicherheitszentrale' },
    { id: 'settings', ico: '⚙', label: 'Einstellungen' },
  ];

  return (
    <div className="app">
      <header className="hdr panel">
        <div className="brand">
          <div className="brand-mark">🛡</div>
          <div>
            <div className="brand-name">Renker<b>Vault</b></div>
            <div className="brand-sub">RENKER INDUSTRIES — SECURE COMMS DIVISION</div>
          </div>
        </div>
        <div className="hdr-status">
          <span className="grp"><span className="led on" /> E2E AKTIV</span>
          <span className="grp">
            <span className={`led ${relayStatus === 'online' ? 'on' : 'off'}`} />
            RELAY {relayStatus === 'online' ? 'ONLINE' : 'OFFLINE'}
          </span>
          <span className="grp mono">{data?.identity.userId}</span>
          <button className="btn ghost" onClick={lockNow}>🔒 Sperren</button>
        </div>
      </header>

      <div className={`mid ${view === 'chats' && activeChatId ? 'chat-open' : ''}`}>
        <nav className="nav panel">
          {nav.map((n, i) => (
            <button
              key={i}
              className={`nav-item ${view === n.id && (n.tab === undefined || tab === n.tab) ? 'active' : ''}`}
              onClick={() => { setView(n.id); if (n.tab) { setTab(n.tab); } }}
            >
              <span className="ico">{n.ico}</span> {n.label}
              {n.label === 'Chats' && unreadTotal > 0 && <span className="badge">{unreadTotal}</span>}
            </button>
          ))}
          <div className="nav-foot">
            ZERO-KNOWLEDGE-RELAY<br />
            DOUBLE RATCHET · X25519<br />
            AES-256-GCM · ARGON2ID
          </div>
        </nav>

        {view === 'chats' && (
          <section className="list panel">
            <div className="list-head">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div className="mono tiny dim">GESICHERTE KANÄLE</div>
                <button
                  className="btn" style={{ marginLeft: 'auto', padding: '4px 8px' }}
                  title="Echte Gruppe erstellen" onClick={() => setShowCreateGroup(true)}
                >
                  + Gruppe
                </button>
              </div>
              <div className="tabs">
                {([['all', 'Alle'], ['direct', '1:1'], ['group', 'Gruppen'], ['channel', 'Kanäle'], ['archived', 'Archiv']] as [Tab, string][]).map(([t, l]) => (
                  <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>{l}</button>
                ))}
              </div>
            </div>
            <div className="search-box">
              <input
                className="input" placeholder="🔎 Chats & Nachrichten durchsuchen…"
                value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <div className="list-body">
              {filteredChats.map((c) => {
                const contact = c.kind === 'direct' && c.origin === 'real' ? data?.contacts[c.id] : undefined;
                return (
                  <div
                    key={c.id}
                    className={`chat-item ${activeChatId === c.id ? 'active' : ''}`}
                    role="button"
                    tabIndex={0}
                    onClick={() => { setActiveChatId(c.id); updateChat(c.id, { unread: 0 }); }}
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { setActiveChatId(c.id); updateChat(c.id, { unread: 0 }); } }}
                  >
                    <div className={`avatar ${c.kind}`}>
                      {c.kind === 'channel' ? '📡' : c.kind === 'group' ? '⬡' : c.name.slice(0, 2).toUpperCase()}
                    </div>
                    {contact && <span className={`presence-dot ${contact.online ? 'on' : 'off'}`} title={contact.online ? 'online' : 'offline'} />}
                    <div className="meta">
                      <div className="nm">
                        {c.pinned && <span className="pin-ico">📌</span>}
                        {c.name} {c.verified && <span className="vbadge">✔</span>}
                        {c.muted && <span className="mute-ico">🔕</span>}
                      </div>
                      <div className="sb">{lastMessagePreview(data?.messages[c.id])}</div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
                      {c.unread > 0 && <span className={`unread ${c.muted ? 'muted' : ''}`}>{c.unread}</span>}
                      <div className="chat-item-menu">
                        <button className="mbtn" title={c.pinned ? 'Lösen' : 'Anpinnen'} onClick={(e) => { e.stopPropagation(); toggleChatFlag(c.id, 'pinned'); }}>📌</button>
                        <button className="mbtn" title={c.muted ? 'Ton an' : 'Stummschalten'} onClick={(e) => { e.stopPropagation(); toggleChatFlag(c.id, 'muted'); }}>🔕</button>
                        <button className="mbtn" title={c.archived ? 'Aus Archiv holen' : 'Archivieren'} onClick={(e) => { e.stopPropagation(); toggleChatFlag(c.id, 'archived'); }}>🗄</button>
                      </div>
                    </div>
                  </div>
                );
              })}
              {filteredChats.length === 0 && (
                <p className="dim tiny" style={{ padding: 14 }}>
                  {duress ? 'Keine Unterhaltungen.' : 'Keine Einträge in diesem Filter.'}
                </p>
              )}
            </div>
          </section>
        )}

        {view === 'chats' && (activeChat && data ? (
          <ChatWindow
            chat={activeChat}
            msgs={data.messages[activeChat.id] ?? []}
            identity={data.identity}
            contactPresence={
              activeChat.kind === 'direct' && activeChat.origin === 'real' && data.contacts[activeChat.id]
                ? { online: !!data.contacts[activeChat.id].online, lastSeen: data.contacts[activeChat.id].lastSeen }
                : undefined
            }
            showCt={showCt}
            typingFrom={typingFrom}
            readReceipts={settings.readReceipts}
            allContacts={allContactsForActive}
            onSend={(t, replyTo) => handleSend(activeChat.id, t, replyTo)}
            onFile={(f) => handleFile(activeChat.id, f)}
            onToggleCt={() => setShowCt((s) => !s)}
            onSetTimer={(sec) => {
              updateChat(activeChat.id, { disappearSec: sec });
              log(ev('info', 'TIMER', `„${activeChat.name}": verschwindende Nachrichten ${sec ? `→ ${sec}s` : 'deaktiviert'}`));
            }}
            onToggleVerified={() => updateChat(activeChat.id, { verified: !activeChat.verified })}
            onRotate={() => rotateChatAny(activeChat.id, 'Manuelle Rotation')}
            onAddMember={(id) => addMemberAny(activeChat.id, id)}
            onRemoveMember={(id) => removeMemberAny(activeChat.id, id)}
            onSetPermission={(memberId, patch) => handleSetPermission(activeChat.id, memberId, patch)}
            onEditMessage={(msgId, newText) => handleEditMessage(activeChat.id, msgId, newText)}
            onDeleteMessage={(msgId) => handleDeleteMessage(activeChat.id, msgId)}
            onReact={(msgId, emoji) => handleReact(activeChat.id, msgId, emoji)}
            onForward={(m) => setForwardMsg(m)}
            onPinMessage={(msgId) => handlePinMessage(activeChat.id, msgId)}
            onBurnChat={() => handleBurnChat(activeChat.id)}
            onBack={() => setActiveChatId(null)}
            onCall={
              activeChat.kind === 'direct' && activeChat.origin === 'real' && !call
                ? (kind) => void startCall(activeChat.id, activeChat.name, kind)
                : undefined
            }
          />
        ) : (
          <main className="main panel">
            <LockVisual
              caption={duress ? 'Bereit' : 'Ende-zu-Ende-Verschlüsselung aktiv'}
              fingerprint={data ? `ID ${data.identity.userId} · GERÄT ${data.identity.deviceName}` : ''}
              stats={[
                { k: 'Sitzungen', v: String(chats.filter((c) => c.kind === 'direct').length) },
                { k: 'Gruppen', v: String(chats.filter((c) => c.kind === 'group').length) },
                { k: 'Kanäle', v: String(chats.filter((c) => c.kind === 'channel').length) },
                { k: 'Relay', v: relayStatus === 'online' ? 'ONLINE' : 'OFFLINE' },
              ]}
            />
          </main>
        ))}

        {view === 'contacts' && (
          <ContactsPage
            chats={chats}
            myUserId={data?.identity.userId ?? ''}
            onOpen={(id) => { setView('chats'); setTab('direct'); setActiveChatId(id); }}
            onToggleVerified={(id) => {
              const c = chats.find((x) => x.id === id);
              updateChat(id, { verified: !c?.verified });
            }}
            onAddContact={() => { setContactError(''); setShowAddContact(true); }}
          />
        )}

        {view === 'security' && data && (
          <SecurityCenter
            identity={data.identity}
            devices={deviceList}
            relayStatus={relayStatus}
            hasDuress={hasDuressPin()}
            integrityResult={integrityResult}
            onApprove={(id) => relayRef.current?.approveDevice(id)}
            onRevoke={(id) => relayRef.current?.revokeDevice(id)}
            onCheckIntegrity={runIntegrityCheck}
            onRotateAll={() => {
              chats.filter((c) => c.kind !== 'direct').forEach((c) => rotateChatAny(c.id, 'Manuelle Rotation'));
            }}
          />
        )}

        {view === 'settings' && data && (
          <SettingsPage
            settings={settings}
            identity={data.identity}
            relayStatus={relayStatus}
            onToggle={(key) => {
              setData((d) => d ? { ...d, settings: { ...d.settings, [key]: !d.settings[key] } } : d);
              log(ev('info', 'SETTINGS', `Einstellung geändert: ${key}`));
            }}
            onSetRelayUrl={(url) => {
              setData((d) => d ? { ...d, settings: { ...d.settings, relayUrl: url || DEFAULT_RELAY_URL } } : d);
              log(ev('info', 'SETTINGS', `Relay-Adresse geändert → ${url || DEFAULT_RELAY_URL}`));
            }}
            onDestroy={destroyAll}
          />
        )}

        <SecurityPanel
          secLog={data?.secLog ?? []}
          relayStatus={relayStatus}
          deviceCount={deviceList.length}
          trustedCount={deviceList.filter((d) => d.trusted).length}
          lastRotation={lastRotation}
          integrity={integrityResult ?? 'OK'}
        />
      </div>

      <ThemeBar
        settings={settings}
        onTheme={(t: ThemeName) => setData((d) => d ? { ...d, settings: { ...d.settings, theme: t } } : d)}
        onAccent={(c) => setData((d) => d ? { ...d, settings: { ...d.settings, accent: c } } : d)}
        onSimIntrusion={simIntrusion}
        onSimTamper={simTamper}
      />

      <AlarmOverlay alarm={alarm} onAck={ackAlarm} onLock={lockNow} />

      <CallOverlay
        call={call}
        onAccept={() => void acceptCall()}
        onDecline={hangupCall}
        onHangup={hangupCall}
        onToggleMute={toggleCallMute}
        onToggleCamera={toggleCallCamera}
      />

      {showAddContact && (
        <AddContactModal
          busy={contactBusy} error={contactError}
          onSubmit={handleAddContact}
          onClose={() => setShowAddContact(false)}
        />
      )}
      {showCreateGroup && (
        <CreateGroupModal
          contacts={realContactsList} busy={false} error={groupError}
          onSubmit={handleCreateGroup}
          onClose={() => setShowCreateGroup(false)}
        />
      )}
      {forwardMsg && (
        <ForwardModal
          message={forwardMsg} chats={chats}
          onForward={doForward}
          onClose={() => setForwardMsg(null)}
        />
      )}
    </div>
  );
}
