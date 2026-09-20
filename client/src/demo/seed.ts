import { newX25519, b64, utf8, aesGcmEncrypt, KeyPair } from '../crypto/primitives';
import { newPqKeyPair } from '../crypto/pq';
import {
  Ratchet, handshakeInitiator, handshakeResponder, newGroupEpochKey,
} from '../crypto/ratchet';
import { safetyNumber, shortFingerprint, groupFingerprint } from '../crypto/safety';
import { Chat, Identity, Message, SecEvent, uid } from '../state/types';

interface PeerSim {
  id: string;
  name: string;
  identity: KeyPair;
  ratchet: Ratchet;
  replies: string[];
  replyIdx: number;
}

interface SymState { key: Uint8Array; epoch: number; }

const peers = new Map<string, PeerSim>();
const myRatchets = new Map<string, Ratchet>();
const symKeys = new Map<string, SymState>();

const REPLY_POOLS: Record<string, string[]> = {
  nadja: [
    'Sounds good. I will check it and reply encrypted.',
    'I just compared the safety number — it matches. ✔',
    'Ok. Remember: none of this over unencrypted channels.',
    'Done. The log is in the vault.',
  ],
  milan: [
    'Understood. The key rotation went through on my end too.',
    'I can send it to you tomorrow as an encrypted attachment.',
    'Good idea. Let us coordinate that in the group channel.',
    'All quiet here, nothing unusual in the security log.',
  ],
  brandt: [
    'Thanks for the info. Discretion as always.',
    'The documents come only over this channel, promised.',
    'Agreed. Please keep the disappearing-messages timer on.',
    'Confirmed.',
  ],
};

async function makePeer(id: string, name: string, myIdentity: KeyPair, stored?: KeyPair): Promise<PeerSim> {
  const peerIdentity = stored ?? newX25519();
  const peerRatchetBase = newX25519();
  const peerPq = newPqKeyPair();

  const { sk, ephPub, pqCipherText } = handshakeInitiator(myIdentity, peerIdentity.pub, peerRatchetBase.pub, peerPq.publicKey);
  const skPeer = handshakeResponder(peerIdentity, peerRatchetBase, myIdentity.pub, ephPub, peerPq.secretKey, pqCipherText);

  const mine = Ratchet.initAlice(sk, peerRatchetBase.pub);
  const theirs = Ratchet.initBob(skPeer, peerRatchetBase);

  await theirs.decrypt(await mine.encrypt(utf8.enc('session-init')));

  const sim: PeerSim = {
    id, name, identity: peerIdentity, ratchet: theirs,
    replies: REPLY_POOLS[id] ?? ['Understood.'], replyIdx: 0,
  };
  peers.set(id, sim);
  myRatchets.set(id, mine);
  return sim;
}

const minsAgo = (m: number) => Date.now() - m * 60_000;

async function directMsg(
  peerId: string, own: boolean, text: string, ts: number, myName: string, myId: string
): Promise<Message> {
  const peer = peers.get(peerId)!;
  const mine = myRatchets.get(peerId)!;
  const sender = own ? mine : peer.ratchet;
  const receiver = own ? peer.ratchet : mine;
  const enc = await sender.encrypt(utf8.enc(text));
  const dec = utf8.dec(await receiver.decrypt(enc));
  return {
    id: uid('m'), from: own ? myId : peerId, fromName: own ? myName : peer.name,
    body: dec, ct: enc.ct, ts, own, kind: 'text',
  };
}

async function symMsg(
  chatId: string, fromId: string, fromName: string, own: boolean, text: string, ts: number
): Promise<Message> {
  const st = symKeys.get(chatId)!;
  const ct = await aesGcmEncrypt(st.key, utf8.enc(text));
  return {
    id: uid('m'), from: fromId, fromName, body: text,
    ct: b64.enc(ct), ts, own, kind: 'text',
  };
}

function sysMsg(text: string, ts: number): Message {
  return { id: uid('s'), from: 'system', fromName: 'System', body: text, ct: '', ts, own: false, kind: 'system' };
}

export interface DemoPeerKey { priv: string; pub: string; name: string; }

export async function buildDemoWorld(identity: Identity): Promise<{
  chats: Chat[]; messages: Record<string, Message[]>; secLog: SecEvent[];
  peerKeys: Record<string, DemoPeerKey>;
}> {
  peers.clear(); myRatchets.clear(); symKeys.clear();
  const myX: KeyPair = { priv: b64.dec(identity.xPriv), pub: b64.dec(identity.xPub) };
  const me = identity.userId;
  const myName = identity.displayName;

  const nadja = await makePeer('nadja', 'Nadja Weiß', myX);
  const milan = await makePeer('milan', 'Milan Kovač', myX);
  const brandt = await makePeer('brandt', 'Dr. A. Brandt', myX);

  const chats: Chat[] = [];
  const messages: Record<string, Message[]> = {};

  const directDefs: { peer: PeerSim; sub: string; script: [boolean, string, number][] }[] = [
    {
      peer: nadja, sub: 'last active 4 min ago',
      script: [
        [false, 'Hey — are you on the new secure channel?', 95],
        [true, 'Yes, RenkerVault is running. We will compare safety numbers shortly.', 92],
        [false, 'Perfect. I no longer use the old messengers for this.', 90],
        [true, 'Good. Here not even the server sees the plaintext.', 88],
        [false, 'Exactly why we are here. Send me the notes when you are ready.', 12],
      ],
    },
    {
      peer: milan, sub: 'last active 26 min ago',
      script: [
        [true, 'Milan, the key rotation for the group is done.', 200],
        [false, 'Clean. The epoch change shows in my security log.', 197],
        [true, 'When your second device joins: confirm it manually first!', 195],
        [false, 'Sure — new devices without confirmation would be exactly the entry point.', 194],
      ],
    },
    {
      peer: brandt, sub: 'disappearing messages: 24 h',
      script: [
        [false, 'The meeting notes only over this channel, please.', 300],
        [true, 'Of course. The timer is set to 24 hours.', 298],
        [false, 'Thanks. Discretion is everything here.', 296],
      ],
    },
  ];

  for (const def of directDefs) {
    const p = def.peer;
    const chatId = p.id;
    const sn = safetyNumber(myX.pub, p.identity.pub);
    chats.push({
      id: chatId, kind: 'direct', origin: 'demo', name: p.name, sub: def.sub,
      members: [
        { id: me, name: myName, role: 'member' },
        { id: p.id, name: p.name, role: 'member' },
      ],
      safetyNumber: sn,
      shortFp: shortFingerprint(b64.dec(b64.enc(p.identity.pub))),
      verified: p.id === 'nadja',
      disappearSec: p.id === 'brandt' ? 86_400 : 0,
      epoch: 1, keyRotatedAt: minsAgo(60), unread: p.id === 'nadja' ? 1 : 0,
    });
    const hist: Message[] = [];
    for (const [own, text, m] of def.script) {
      hist.push(await directMsg(p.id, own, text, minsAgo(m), myName, me));
    }
    messages[chatId] = hist;
  }

  const gid = 'grp-werkstatt';
  symKeys.set(gid, { key: newGroupEpochKey(), epoch: 3 });
  const gFp = groupFingerprint(symKeys.get(gid)!.key, 3);
  chats.push({
    id: gid, kind: 'group', origin: 'demo', name: 'Werkstatt Nord', sub: '4 members · E2E (epoch 3)',
    members: [
      { id: me, name: myName, role: 'owner' },
      { id: 'nadja', name: 'Nadja Weiß', role: 'admin' },
      { id: 'milan', name: 'Milan Kovač', role: 'member' },
      { id: 'brandt', name: 'Dr. A. Brandt', role: 'member' },
    ],
    safetyNumber: '', shortFp: gFp, verified: false,
    disappearSec: 0, epoch: 3, keyRotatedAt: minsAgo(75), unread: 2,
  });
  messages[gid] = [
    sysMsg('Group created · end-to-end encrypted (epoch 1)', minsAgo(600)),
    await symMsg(gid, 'nadja', 'Nadja Weiß', false, 'Welcome to the workshop secure group channel.', minsAgo(590)),
    await symMsg(gid, me, myName, true, 'Thanks! Everyone please check the device list once.', minsAgo(585)),
    sysMsg('Milan Kovač was added · keys re-distributed (epoch 2)', minsAgo(400)),
    await symMsg(gid, 'milan', 'Milan Kovač', false, 'I am in. The group fingerprint matches on my end.', minsAgo(395)),
    sysMsg('Key rotation by the owner · epoch 3 active', minsAgo(75)),
    await symMsg(gid, 'brandt', 'Dr. A. Brandt', false, 'Rotation arrived on my end. All green.', minsAgo(70)),
  ];

  const cid = 'ch-bulletin';
  symKeys.set(cid, { key: newGroupEpochKey(), epoch: 1 });
  const cFp = groupFingerprint(symKeys.get(cid)!.key, 1);
  chats.push({
    id: cid, kind: 'channel', origin: 'demo', name: 'RENKER BULLETIN', sub: 'Broadcast · 132 subscribers · read-only',
    members: [
      { id: me, name: myName, role: 'owner' },
      { id: 'nadja', name: 'Nadja Weiß', role: 'admin' },
    ],
    safetyNumber: '', shortFp: cFp, verified: false,
    disappearSec: 0, epoch: 1, keyRotatedAt: minsAgo(1440),
    subscriberCount: 132, unread: 0,
  });
  messages[cid] = [
    sysMsg('Channel created · broadcast mode (owners/admins send, subscribers read)', minsAgo(2000)),
    await symMsg(cid, me, myName, true, '📢 RenkerVault v0.1 is live. Report suspicious device requests immediately.', minsAgo(1400)),
    await symMsg(cid, 'nadja', 'Nadja Weiß', false, 'Reminder: re-compare safety numbers after every key change.', minsAgo(700)),
  ];

  const peerKeys: Record<string, DemoPeerKey> = {};
  for (const p of [nadja, milan, brandt]) {
    peerKeys[p.id] = { priv: b64.enc(p.identity.priv), pub: b64.enc(p.identity.pub), name: p.name };
  }

  const secLog: SecEvent[] = [
    { id: uid('e'), ts: minsAgo(1500), severity: 'info', kind: 'VAULT_INIT', text: 'Local vault created (AES-256-GCM, Argon2id)' },
    { id: uid('e'), ts: minsAgo(1499), severity: 'info', kind: 'KEYGEN', text: 'Identity keys generated (X25519 + Ed25519)' },
    { id: uid('e'), ts: minsAgo(600), severity: 'info', kind: 'SESSION', text: 'Double Ratchet sessions established with 3 contacts' },
    { id: uid('e'), ts: minsAgo(75), severity: 'info', kind: 'KEY_ROTATION', text: 'Group key "Werkstatt Nord" rotated → epoch 3' },
    { id: uid('e'), ts: minsAgo(4), severity: 'info', kind: 'VAULT_CHECK', text: 'Integrity check of the local database: OK' },
  ];

  return { chats, messages, secLog, peerKeys };
}

export async function restoreDemoSessions(
  identity: Identity,
  peerKeys: Record<string, DemoPeerKey>,
  symChats: { id: string; epoch: number }[]
): Promise<Record<string, { epoch: number; fp: string }>> {
  peers.clear(); myRatchets.clear(); symKeys.clear();
  const myX: KeyPair = { priv: b64.dec(identity.xPriv), pub: b64.dec(identity.xPub) };
  for (const [id, k] of Object.entries(peerKeys)) {
    await makePeer(id, k.name, myX, { priv: b64.dec(k.priv), pub: b64.dec(k.pub) });
  }
  const out: Record<string, { epoch: number; fp: string }> = {};
  for (const c of symChats) {
    const epoch = c.epoch + 1;
    const key = newGroupEpochKey();
    symKeys.set(c.id, { key, epoch });
    out[c.id] = { epoch, fp: groupFingerprint(key, epoch) };
  }
  return out;
}

export async function demoSendDirect(peerId: string, text: string): Promise<{ ct: string }> {
  const mine = myRatchets.get(peerId);
  const peer = peers.get(peerId);
  if (!mine || !peer) throw new Error('unknown contact');
  const enc = await mine.encrypt(utf8.enc(text));
  await peer.ratchet.decrypt(enc);
  return { ct: enc.ct };
}

export async function demoPeerReply(peerId: string): Promise<{ text: string; ct: string } | null> {
  const mine = myRatchets.get(peerId);
  const peer = peers.get(peerId);
  if (!mine || !peer) return null;
  const text = peer.replies[peer.replyIdx % peer.replies.length];
  peer.replyIdx += 1;
  const enc = await peer.ratchet.encrypt(utf8.enc(text));
  const dec = utf8.dec(await mine.decrypt(enc));
  return { text: dec, ct: enc.ct };
}

export function demoPeerName(peerId: string): string {
  return peers.get(peerId)?.name ?? peerId;
}

export async function demoSendSym(chatId: string, text: string): Promise<{ ct: string }> {
  const st = symKeys.get(chatId);
  if (!st) throw new Error('unknown group / unknown channel');
  const ct = await aesGcmEncrypt(st.key, utf8.enc(text));
  return { ct: b64.enc(ct) };
}

export function demoRotateEpoch(chatId: string): { epoch: number; fp: string } {
  const st = symKeys.get(chatId);
  if (!st) throw new Error('unknown group / unknown channel');
  st.key = newGroupEpochKey();
  st.epoch += 1;
  return { epoch: st.epoch, fp: groupFingerprint(st.key, st.epoch) };
}

export async function demoEncryptFile(
  chatId: string, kind: 'direct' | 'sym', bytes: Uint8Array
): Promise<{ ct: string }> {
  if (kind === 'direct') {
    const mine = myRatchets.get(chatId)!;
    const peer = peers.get(chatId)!;
    const enc = await mine.encrypt(bytes);
    await peer.ratchet.decrypt(enc);
    return { ct: enc.ct };
  }
  const st = symKeys.get(chatId)!;
  return { ct: b64.enc(await aesGcmEncrypt(st.key, bytes)) };
}
