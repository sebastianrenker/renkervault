/**
 * Demo-Welt mit simulierten Gesprächspartnern.
 * ============================================
 * WICHTIG: Das ist KEINE Fake-Krypto-Anzeige. Jede Demo-Nachricht läuft
 * wirklich durch die Double-Ratchet- bzw. Epoch-Key-Verschlüsselung:
 * die "Peers" leben im selben Browser-Prozess, besitzen echte Schlüssel-
 * paare und ent-/verschlüsseln real. Der angezeigte Chiffretext ist der
 * tatsächliche AES-GCM-Output. Für den Betrieb über den Relay-Server
 * werden dieselben Envelopes über WebSocket geschickt (net/client.ts).
 */
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
  ratchet: Ratchet;      // Ratchet-Ende des Peers
  replies: string[];
  replyIdx: number;
}

interface SymState { key: Uint8Array; epoch: number; }

// Sitzungs-Zustand (nur RAM; Sitzungen werden pro App-Start frisch ausgehandelt)
const peers = new Map<string, PeerSim>();
const myRatchets = new Map<string, Ratchet>();
const symKeys = new Map<string, SymState>(); // Gruppen-/Kanal-Epoch-Keys

const REPLY_POOLS: Record<string, string[]> = {
  nadja: [
    'Klingt gut. Ich prüfe das und melde mich verschlüsselt zurück.',
    'Safety Number habe ich eben verglichen — stimmt überein. ✔',
    'Ok. Denk dran: nichts davon über unverschlüsselte Kanäle.',
    'Erledigt. Log liegt im Tresor.',
  ],
  milan: [
    'Verstanden. Schlüsselrotation ist bei mir auch durchgelaufen.',
    'Kann ich dir morgen als verschlüsselten Anhang schicken.',
    'Gute Idee. Lass uns das im Gruppenkanal abstimmen.',
    'Alles ruhig hier, keine Auffälligkeiten im Security-Log.',
  ],
  brandt: [
    'Danke für die Info. Diskretion wie immer.',
    'Die Unterlagen kommen nur über diesen Kanal, versprochen.',
    'Einverstanden. Timer für verschwindende Nachrichten bitte anlassen.',
    'Bestätigt.',
  ],
};

/** Direkten Demo-Kontakt anlegen: echter Handshake + zwei Ratchet-Enden. */
async function makePeer(id: string, name: string, myIdentity: KeyPair, stored?: KeyPair): Promise<PeerSim> {
  const peerIdentity = stored ?? newX25519();
  const peerRatchetBase = newX25519();
  const peerPq = newPqKeyPair(); // Demo-Peer als Responder: ML-KEM-Prekey (nicht persistiert)

  // X3DH-lite (hybrid, siehe crypto/ratchet.ts): Ich (Initiator) <-> Peer
  // (Responder). peerRatchetBase dient zugleich als Peers veröffentlichter
  // X25519-Prekey, peerPq.publicKey als sein ML-KEM-768-Prekey.
  const { sk, ephPub, pqCipherText } = handshakeInitiator(myIdentity, peerIdentity.pub, peerRatchetBase.pub, peerPq.publicKey);
  const skPeer = handshakeResponder(peerIdentity, peerRatchetBase, myIdentity.pub, ephPub, peerPq.secretKey, pqCipherText);

  const mine = Ratchet.initAlice(sk, peerRatchetBase.pub);
  const theirs = Ratchet.initBob(skPeer, peerRatchetBase);

  // Session-Priming: Der Responder kann im Double Ratchet erst senden,
  // nachdem er die erste Initiator-Nachricht empfangen hat (DH-Ratchet-
  // Schritt initialisiert seine Sendekette). Daher läuft direkt nach dem
  // Handshake eine stille Bestätigungsnachricht durch die Sitzung.
  await theirs.decrypt(await mine.encrypt(utf8.enc('session-init')));

  const sim: PeerSim = {
    id, name, identity: peerIdentity, ratchet: theirs,
    replies: REPLY_POOLS[id] ?? ['Verstanden.'], replyIdx: 0,
  };
  peers.set(id, sim);
  myRatchets.set(id, mine);
  return sim;
}

const minsAgo = (m: number) => Date.now() - m * 60_000;

/** 1:1-Nachricht durch beide echten Ratchet-Enden schicken. */
async function directMsg(
  peerId: string, own: boolean, text: string, ts: number, myName: string, myId: string
): Promise<Message> {
  const peer = peers.get(peerId)!;
  const mine = myRatchets.get(peerId)!;
  const sender = own ? mine : peer.ratchet;
  const receiver = own ? peer.ratchet : mine;
  const enc = await sender.encrypt(utf8.enc(text));
  const dec = utf8.dec(await receiver.decrypt(enc)); // echte Entschlüsselung
  return {
    id: uid('m'), from: own ? myId : peerId, fromName: own ? myName : peer.name,
    body: dec, ct: enc.ct, ts, own, kind: 'text',
  };
}

/** Gruppen-/Kanalnachricht mit Epoch-Key verschlüsseln. */
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

// ---------------------------------------------------------------------------
// Öffentliche Demo-API
// ---------------------------------------------------------------------------
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

  // --- 3 Einzelchats -------------------------------------------------------
  const directDefs: { peer: PeerSim; sub: string; script: [boolean, string, number][] }[] = [
    {
      peer: nadja, sub: 'zuletzt aktiv vor 4 min',
      script: [
        [false, 'Hey — bist du auf dem neuen sicheren Kanal?', 95],
        [true, 'Ja, RenkerVault läuft. Safety Number vergleichen wir gleich.', 92],
        [false, 'Perfekt. Die alten Messenger nutze ich dafür nicht mehr.', 90],
        [true, 'Gut so. Hier sieht nicht mal der Server den Klartext.', 88],
        [false, 'Genau deshalb sind wir hier. Schick mir die Notizen, wenn du soweit bist.', 12],
      ],
    },
    {
      peer: milan, sub: 'zuletzt aktiv vor 26 min',
      script: [
        [true, 'Milan, die Schlüsselrotation für die Gruppe ist durch.', 200],
        [false, 'Sauber. Epoch-Wechsel wird bei mir im Security-Log angezeigt.', 197],
        [true, 'Wenn dein zweites Gerät dazukommt: erst manuell bestätigen!', 195],
        [false, 'Klar — neue Geräte ohne Bestätigung wären ja genau das Einfallstor.', 194],
      ],
    },
    {
      peer: brandt, sub: 'verschwindende Nachrichten: 24 h',
      script: [
        [false, 'Die Besprechungsnotizen bitte nur über diesen Kanal.', 300],
        [true, 'Selbstverständlich. Timer steht auf 24 Stunden.', 298],
        [false, 'Danke. Diskretion ist hier alles.', 296],
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
      verified: p.id === 'nadja', // eine verifizierte Demo-Beziehung
      disappearSec: p.id === 'brandt' ? 86_400 : 0,
      epoch: 1, keyRotatedAt: minsAgo(60), unread: p.id === 'nadja' ? 1 : 0,
    });
    const hist: Message[] = [];
    for (const [own, text, m] of def.script) {
      hist.push(await directMsg(p.id, own, text, minsAgo(m), myName, me));
    }
    messages[chatId] = hist;
  }

  // --- 1 Gruppenchat -------------------------------------------------------
  const gid = 'grp-werkstatt';
  symKeys.set(gid, { key: newGroupEpochKey(), epoch: 3 });
  const gFp = groupFingerprint(symKeys.get(gid)!.key, 3);
  chats.push({
    id: gid, kind: 'group', origin: 'demo', name: 'Werkstatt Nord', sub: '4 Mitglieder · E2E (Epoche 3)',
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
    sysMsg('Gruppe erstellt · Ende-zu-Ende-verschlüsselt (Epoche 1)', minsAgo(600)),
    await symMsg(gid, 'nadja', 'Nadja Weiß', false, 'Willkommen im sicheren Gruppenkanal der Werkstatt.', minsAgo(590)),
    await symMsg(gid, me, myName, true, 'Danke! Bitte alle einmal die Geräteliste prüfen.', minsAgo(585)),
    sysMsg('Milan Kovač wurde hinzugefügt · Schlüssel neu verteilt (Epoche 2)', minsAgo(400)),
    await symMsg(gid, 'milan', 'Milan Kovač', false, 'Bin drin. Fingerprint der Gruppe stimmt bei mir.', minsAgo(395)),
    sysMsg('Schlüsselrotation durch Owner · Epoche 3 aktiv', minsAgo(75)),
    await symMsg(gid, 'brandt', 'Dr. A. Brandt', false, 'Rotation bei mir angekommen. Alles grün.', minsAgo(70)),
  ];

  // --- 1 Kanal -------------------------------------------------------------
  const cid = 'ch-bulletin';
  symKeys.set(cid, { key: newGroupEpochKey(), epoch: 1 });
  const cFp = groupFingerprint(symKeys.get(cid)!.key, 1);
  chats.push({
    id: cid, kind: 'channel', origin: 'demo', name: 'RENKER BULLETIN', sub: 'Broadcast · 132 Abonnenten · read-only',
    members: [
      { id: me, name: myName, role: 'owner' },
      { id: 'nadja', name: 'Nadja Weiß', role: 'admin' },
    ],
    safetyNumber: '', shortFp: cFp, verified: false,
    disappearSec: 0, epoch: 1, keyRotatedAt: minsAgo(1440),
    subscriberCount: 132, unread: 0,
  });
  messages[cid] = [
    sysMsg('Kanal erstellt · Broadcast-Modus (Owner/Admins senden, Abonnenten lesen)', minsAgo(2000)),
    await symMsg(cid, me, myName, true, '📢 RenkerVault v0.1 ist live. Meldet verdächtige Geräte-Anfragen sofort.', minsAgo(1400)),
    await symMsg(cid, 'nadja', 'Nadja Weiß', false, 'Reminder: Safety Numbers nach jedem Schlüsselwechsel neu vergleichen.', minsAgo(700)),
  ];

  const peerKeys: Record<string, DemoPeerKey> = {};
  for (const p of [nadja, milan, brandt]) {
    peerKeys[p.id] = { priv: b64.enc(p.identity.priv), pub: b64.enc(p.identity.pub), name: p.name };
  }

  const secLog: SecEvent[] = [
    { id: uid('e'), ts: minsAgo(1500), severity: 'info', kind: 'VAULT_INIT', text: 'Lokaler Vault erstellt (AES-256-GCM, Argon2id)' },
    { id: uid('e'), ts: minsAgo(1499), severity: 'info', kind: 'KEYGEN', text: 'Identitätsschlüssel erzeugt (X25519 + Ed25519)' },
    { id: uid('e'), ts: minsAgo(600), severity: 'info', kind: 'SESSION', text: 'Double-Ratchet-Sitzungen mit 3 Kontakten etabliert' },
    { id: uid('e'), ts: minsAgo(75), severity: 'info', kind: 'KEY_ROTATION', text: 'Gruppenschlüssel „Werkstatt Nord" rotiert → Epoche 3' },
    { id: uid('e'), ts: minsAgo(4), severity: 'info', kind: 'VAULT_CHECK', text: 'Integritätsprüfung der lokalen Datenbank: OK' },
  ];

  return { chats, messages, secLog, peerKeys };
}

/**
 * Sitzungen nach App-Neustart wiederherstellen: Peer-IDENTITÄTEN bleiben
 * stabil (Safety Numbers ändern sich nicht), aber Ratchet-Sitzungen und
 * Gruppen-Epoch-Keys werden frisch ausgehandelt (Prototyp: Sitzungszustand
 * wird bewusst nicht persistiert). Gruppen/Kanäle bekommen eine neue Epoche.
 */
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

/** Eigene 1:1-Nachricht real verschlüsseln (Peer entschlüsselt zur Kontrolle). */
export async function demoSendDirect(peerId: string, text: string): Promise<{ ct: string }> {
  const mine = myRatchets.get(peerId);
  const peer = peers.get(peerId);
  if (!mine || !peer) throw new Error('Unbekannter Kontakt');
  const enc = await mine.encrypt(utf8.enc(text));
  await peer.ratchet.decrypt(enc); // Roundtrip-Nachweis
  return { ct: enc.ct };
}

/** Simulierte Antwort des Peers (echte Ratchet-Verschlüsselung in Gegenrichtung). */
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

/** Gruppen-/Kanalnachricht mit aktuellem Epoch-Key verschlüsseln. */
export async function demoSendSym(chatId: string, text: string): Promise<{ ct: string }> {
  const st = symKeys.get(chatId);
  if (!st) throw new Error('Unbekannte Gruppe / unbekannter Kanal');
  const ct = await aesGcmEncrypt(st.key, utf8.enc(text));
  return { ct: b64.enc(ct) };
}

/** Rekeying: neue Epoche (z. B. nach Mitgliederänderung oder manuell). */
export function demoRotateEpoch(chatId: string): { epoch: number; fp: string } {
  const st = symKeys.get(chatId);
  if (!st) throw new Error('Unbekannte Gruppe / unbekannter Kanal');
  st.key = newGroupEpochKey();
  st.epoch += 1;
  return { epoch: st.epoch, fp: groupFingerprint(st.key, st.epoch) };
}

/** Datei-Anhang verschlüsseln (1:1 über Ratchet, Gruppe/Kanal über Epoch-Key). */
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
