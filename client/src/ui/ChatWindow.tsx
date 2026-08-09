import { Fragment, ReactNode, useEffect, useRef, useState } from 'react';
import { Chat, Identity, Member, MemberPermissions, Message, ReplyRef } from '../state/types';

const TIMERS: { sec: number; label: string }[] = [
  { sec: 0, label: 'Aus' },
  { sec: 30, label: '30 Sek.' },
  { sec: 300, label: '5 Min.' },
  { sec: 3600, label: '1 Std.' },
  { sec: 86400, label: '24 Std.' },
];

const QUICK_REACTIONS = ['👍', '❤️', '😂', '😮', '😢', '🙏'];

const fmtTime = (ts: number) =>
  new Date(ts).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });

function QrLike({ data }: { data: string }) {
  const N = 21;
  const cells: boolean[] = [];
  let acc = 7;
  for (let i = 0; i < N * N; i++) {
    acc = (acc * 31 + data.charCodeAt(i % data.length) + i) >>> 0;
    cells.push((acc & 5) === 5 || (acc % 7) < 2);
  }
  return (
    <svg width="168" height="168" viewBox={`0 0 ${N} ${N}`} className="qr">
      <rect width={N} height={N} fill="var(--raised)" />
      {cells.map((on, i) =>
        on ? (
          <rect key={i} x={i % N} y={Math.floor(i / N)} width="1" height="1" fill="var(--accent)" />
        ) : null
      )}
    </svg>
  );
}

const URL_OR_MENTION = /(https?:\/\/\S+|@\w+)/g;

function renderRichText(text: string, members: Member[]): ReactNode {
  const parts = text.split(URL_OR_MENTION);
  return parts.map((part, i) => {
    if (/^https?:\/\//.test(part)) {
      return (
        <a key={i} href={part} target="_blank" rel="noopener noreferrer" className="link">
          {part}
        </a>
      );
    }
    if (part.startsWith('@')) {
      const token = part.slice(1).toLowerCase();
      const hit = members.some((m) => m.name.toLowerCase().split(/\s+/)[0] === token);
      if (hit) return <span key={i} className="mention">{part}</span>;
    }
    return <Fragment key={i}>{part}</Fragment>;
  });
}

export function ChatWindow(props: {
  chat: Chat;
  msgs: Message[];
  identity: Identity;
  contactPresence?: { online: boolean; lastSeen?: number };
  showCt: boolean;
  typingFrom: string | null;
  readReceipts: boolean;
  allContacts: { id: string; name: string }[];
  onSend: (text: string, replyTo?: ReplyRef) => void;
  onFile: (file: File) => void;
  onToggleCt: () => void;
  onSetTimer: (sec: number) => void;
  onToggleVerified: () => void;
  onRotate: () => void;
  onAddMember: (id: string) => void;
  onRemoveMember: (id: string) => void;
  onSetPermission: (memberId: string, patch: Partial<MemberPermissions>) => void;
  onEditMessage: (msgId: string, newText: string) => void;
  onDeleteMessage: (msgId: string) => void;
  onReact: (msgId: string, emoji: string) => void;
  onForward: (msg: Message) => void;
  onPinMessage: (msgId: string | null) => void;
  onBurnChat: () => void;
  onBack?: () => void;
  onCall?: (kind: 'audio' | 'video') => void;
}) {
  const { chat, msgs, identity } = props;
  const [text, setText] = useState('');
  const [modal, setModal] = useState<'safety' | 'members' | null>(null);
  const [replyingTo, setReplyingTo] = useState<Message | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [reactPickerFor, setReactPickerFor] = useState<string | null>(null);
  const [burnConfirm, setBurnConfirm] = useState(false);
  const [recording, setRecording] = useState(false);
  const [recSeconds, setRecSeconds] = useState(0);
  const endRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const recChunksRef = useRef<Blob[]>([]);
  const recTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [msgs.length, props.typingFrom]);

  useEffect(() => {
    setReplyingTo(null); setEditingId(null); setText(''); setReactPickerFor(null); setBurnConfirm(false);
  }, [chat.id]);

  const myRole = chat.members.find((m) => m.id === identity.userId)?.role ?? 'member';
  const isOwner = myRole === 'owner';
  const isAdmin = myRole === 'owner' || myRole === 'admin';
  const myPerms = chat.members.find((m) => m.id === identity.userId)?.permissions;
  const canPost = chat.kind !== 'channel' || isOwner || (myRole === 'admin' && (myPerms?.canPost ?? true));
  const canInvite = isOwner || (myRole === 'admin' && (myPerms?.canInvite ?? true));
  const canRemove = isOwner || (myRole === 'admin' && (myPerms?.canRemove ?? true));
  const canPin = chat.kind === 'direct' || isOwner || (myRole === 'admin' && (myPerms?.canPin ?? true));
  const addable = props.allContacts.filter((c) => !chat.members.some((m) => m.id === c.id));
  const pinnedMsg = chat.pinnedMessageId ? msgs.find((m) => m.id === chat.pinnedMessageId) : null;

  const submit = () => {
    const t = text.trim();
    if (!t) return;
    if (editingId) {
      props.onEditMessage(editingId, t);
      setEditingId(null);
    } else {
      props.onSend(t, replyingTo ? { id: replyingTo.id, fromName: replyingTo.fromName, preview: replyingTo.body.slice(0, 80) } : undefined);
      setReplyingTo(null);
    }
    setText('');
  };

  const startReply = (m: Message) => { setEditingId(null); setReplyingTo(m); };
  const startEdit = (m: Message) => { setReplyingTo(null); setEditingId(m.id); setText(m.body); };

  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const rec = new MediaRecorder(stream);
      recChunksRef.current = [];
      rec.ondataavailable = (e) => { if (e.data.size > 0) recChunksRef.current.push(e.data); };
      rec.onstop = () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(recChunksRef.current, { type: 'audio/webm' });
        const file = new File([blob], `sprachnachricht-${Date.now()}.webm`, { type: 'audio/webm' });
        props.onFile(file);
      };
      recorderRef.current = rec;
      rec.start();
      setRecording(true);
      setRecSeconds(0);
      recTimerRef.current = setInterval(() => setRecSeconds((s) => s + 1), 1000);
    } catch {
      alert('Mikrofonzugriff nicht möglich (Berechtigung verweigert oder nicht verfügbar).');
    }
  };

  const stopRecording = () => {
    recorderRef.current?.stop();
    recorderRef.current = null;
    setRecording(false);
    if (recTimerRef.current) clearInterval(recTimerRef.current);
  };

  const kindLabel =
    chat.kind === 'direct' ? 'Ende-zu-Ende · Double Ratchet'
    : chat.kind === 'group' ? `Gruppe · E2E · Epoche ${chat.epoch}`
    : `Kanal · Broadcast · Epoche ${chat.epoch}`;

  return (
    <main className="main panel">
      <div className="chat-head">
        {props.onBack && (
          <button className="iconbtn back-btn" title="Zurück zur Chat-Liste" onClick={props.onBack}>‹</button>
        )}
        <div className={`avatar ${chat.kind}`}>
          {chat.kind === 'channel' ? '📡' : chat.kind === 'group' ? '⬡' : chat.name.slice(0, 2).toUpperCase()}
        </div>
        <div className="titles">
          <h2>
            {chat.name}{' '}
            {chat.verified && <span className="vbadge" title="Safety Number verifiziert">✔ verifiziert</span>}
            {chat.muted && <span className="dim tiny" title="Stummgeschaltet"> 🔕</span>}
          </h2>
          <div className="fp">
            🔒 {kindLabel} · FP <b>{chat.shortFp}</b>
          </div>
          {props.contactPresence && (
            <div className="online-line">
              <span className={`led ${props.contactPresence.online ? 'on' : 'off'}`} />
              {props.contactPresence.online
                ? 'online'
                : props.contactPresence.lastSeen
                  ? `zuletzt online ${fmtTime(props.contactPresence.lastSeen)}`
                  : 'offline'}
            </div>
          )}
        </div>
        <div className="chat-actions">
          {props.onCall && (
            <>
              <button className="iconbtn" onClick={() => props.onCall!('audio')} title="Sprachanruf">📞</button>
              <button className="iconbtn" onClick={() => props.onCall!('video')} title="Videoanruf">📹</button>
            </>
          )}
          <select
            className="input tiny"
            style={{ width: 'auto', padding: '5px 8px' }}
            value={chat.disappearSec}
            onChange={(e) => props.onSetTimer(Number(e.target.value))}
            title="Verschwindende Nachrichten"
          >
            {TIMERS.map((t) => (
              <option key={t.sec} value={t.sec}>⏳ {t.label}</option>
            ))}
          </select>
          <button
            className={`iconbtn ${props.showCt ? 'active' : ''}`}
            onClick={props.onToggleCt}
            title="Chiffretext anzeigen (Nachweis der Verschlüsselung)"
          >
            CT
          </button>
          <button className="iconbtn" onClick={() => setModal('safety')} title="Schlüssel verifizieren">
            🛡
          </button>
          {chat.kind !== 'direct' && (
            <button className="iconbtn" onClick={() => setModal('members')} title="Mitglieder">
              👥
            </button>
          )}
          <button
            className={`iconbtn ${burnConfirm ? 'active' : ''}`}
            style={burnConfirm ? { color: 'var(--danger)', borderColor: 'var(--danger)' } : undefined}
            onClick={() => {
              if (burnConfirm) { props.onBurnChat(); setBurnConfirm(false); }
              else {
                setBurnConfirm(true);
                setTimeout(() => setBurnConfirm(false), 4000);
              }
            }}
            title={burnConfirm ? 'Wirklich unwiderruflich löschen? Nochmal klicken zum Bestätigen' : 'Sitzung verbrennen — kompletten Verlauf sofort unwiderruflich löschen'}
          >
            {burnConfirm ? '⚠ Sicher?' : '🔥'}
          </button>
        </div>
      </div>

      {pinnedMsg && (
        <div className="pinned-banner">
          <span className="ico">📌</span>
          <div className="ptxt">
            <b>{pinnedMsg.fromName}</b>: {pinnedMsg.deleted ? 'Nachricht gelöscht' : pinnedMsg.body.slice(0, 90)}
          </div>
          {canPin && (
            <button className="iconbtn" title="Lösen" onClick={() => props.onPinMessage(null)}>✕</button>
          )}
        </div>
      )}

      <div className="msgs">
        {msgs.map((m) => (
          <div
            key={m.id}
            className={`msg ${m.own ? 'own' : ''} ${m.kind === 'system' ? 'system' : ''}`}
            onMouseLeave={() => { if (reactPickerFor === m.id) setReactPickerFor(null); }}
          >
            {m.kind !== 'system' && (
              <div className="msg-actionbar">
                <button className="mbtn" title="Reagieren" onClick={() => setReactPickerFor(reactPickerFor === m.id ? null : m.id)}>😊</button>
                <button className="mbtn" title="Antworten" onClick={() => startReply(m)}>↩</button>
                <button className="mbtn" title="Weiterleiten" onClick={() => props.onForward(m)}>➦</button>
                {!m.deleted && (
                  <button className="mbtn" title="Kopieren" onClick={() => navigator.clipboard?.writeText(m.body)}>⧉</button>
                )}
                {canPin && (
                  <button className="mbtn" title={chat.pinnedMessageId === m.id ? 'Lösen' : 'Anheften'}
                    onClick={() => props.onPinMessage(chat.pinnedMessageId === m.id ? null : m.id)}>📌</button>
                )}
                {m.own && !m.deleted && m.kind === 'text' && (
                  <button className="mbtn" title="Bearbeiten" onClick={() => startEdit(m)}>✎</button>
                )}
                {(m.own || isOwner) && !m.deleted && (
                  <button className="mbtn dangerous" title="Löschen" onClick={() => props.onDeleteMessage(m.id)}>🗑</button>
                )}
              </div>
            )}
            {reactPickerFor === m.id && (
              <div className="react-picker">
                {QUICK_REACTIONS.map((e) => (
                  <button key={e} onClick={() => { props.onReact(m.id, e); setReactPickerFor(null); }}>{e}</button>
                ))}
              </div>
            )}
            <div className="bubble">
              {!m.own && m.kind !== 'system' && chat.kind !== 'direct' && (
                <div className="who">{m.fromName}</div>
              )}
              {m.forwardedFrom && !m.deleted && (
                <div className="fwd-tag">➦ Weitergeleitet von {m.forwardedFrom}</div>
              )}
              {m.replyTo && !m.deleted && (
                <div className="quote">
                  <b>{m.replyTo.fromName}</b>
                  <div>{m.replyTo.preview}</div>
                </div>
              )}
              {m.deleted ? (
                <span className="deleted-note">🗑 Nachricht gelöscht</span>
              ) : m.kind === 'file' ? (
                m.fileMime?.startsWith('image/') && m.fileDataUrl ? (
                  <img src={m.fileDataUrl} alt={m.fileName} className="msg-image" />
                ) : m.fileMime?.startsWith('audio/') && m.fileDataUrl ? (
                  <div className="voice-msg">
                    <span>🎤</span>
                    <audio controls src={m.fileDataUrl} />
                  </div>
                ) : (
                  <div className="filechip">📎 {m.fileName} <span className="dim">({Math.round((m.fileSize ?? 0) / 1024)} KB · verschlüsselt)</span></div>
                )
              ) : (
                renderRichText(m.body, chat.members)
              )}
              {props.showCt && m.ct && !m.deleted && (
                <div className="ctline">
                  <b>CT»</b> {m.ct.slice(0, 96)}{m.ct.length > 96 ? '…' : ''}
                </div>
              )}
            </div>
            {m.reactions && Object.keys(m.reactions).length > 0 && (
              <div className="reactions-row">
                {Object.entries(m.reactions).filter(([, ids]) => ids.length > 0).map(([emoji, ids]) => (
                  <button
                    key={emoji}
                    className={`reaction-chip ${ids.includes(identity.userId) ? 'mine' : ''}`}
                    onClick={() => props.onReact(m.id, emoji)}
                  >
                    {emoji} {ids.length}
                  </button>
                ))}
              </div>
            )}
            {m.kind !== 'system' && (
              <div className="foot">
                <span>{fmtTime(m.ts)}</span>
                {m.edited && !m.deleted && <span title="bearbeitet">bearbeitet</span>}
                {m.expiresAt && <span title="verschwindet automatisch">⏳</span>}
                {m.own && (
                  <span>{props.readReceipts && m.readByPeer ? '✓✓' : '✓'}</span>
                )}
              </div>
            )}
          </div>
        ))}
        <div ref={endRef} />
      </div>

      {props.typingFrom && <div className="typing">▸ {props.typingFrom} schreibt…</div>}

      {canPost ? (
        <>
          {(replyingTo || editingId) && (
            <div className="compose-context">
              <div className="cc-txt">
                {editingId ? (
                  <><b>Nachricht bearbeiten</b></>
                ) : (
                  <><b>Antwort an {replyingTo!.fromName}</b><div className="dim">{replyingTo!.body.slice(0, 90)}</div></>
                )}
              </div>
              <button className="iconbtn" onClick={() => { setReplyingTo(null); setEditingId(null); setText(''); }}>✕</button>
            </div>
          )}
          <div className="composer">
            <button className="iconbtn" title="Verschlüsselten Anhang senden" onClick={() => fileRef.current?.click()}>
              📎
            </button>
            <input
              ref={fileRef}
              type="file"
              hidden
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) props.onFile(f);
                e.target.value = '';
              }}
            />
            <input
              className="input"
              placeholder={`Verschlüsselte Nachricht an ${chat.name}…`}
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && submit()}
            />
            {recording ? (
              <button className="btn dangerous" onClick={stopRecording}>
                ⏺ {String(Math.floor(recSeconds / 60)).padStart(2, '0')}:{String(recSeconds % 60).padStart(2, '0')} · Stopp
              </button>
            ) : (
              <button className="iconbtn" title="Sprachnachricht aufnehmen" onClick={startRecording}>🎤</button>
            )}
            <button className="btn solid" onClick={submit}>{editingId ? 'Speichern' : 'Senden 🔒'}</button>
          </div>
        </>
      ) : (
        <div className="composer-note">📡 Broadcast-Kanal — nur Owner/Admins können senden. Du liest mit.</div>
      )}

      {modal === 'safety' && (
        <div className="modal-back" onClick={() => setModal(null)}>
          <div className="modal panel" onClick={(e) => e.stopPropagation()}>
            <h3>🛡 Schlüssel verifizieren — {chat.name}</h3>
            {chat.kind === 'direct' ? (
              <>
                <p className="gate-info">
                  Vergleiche diese Safety Number über einen zweiten Kanal (persönlich,
                  Telefonat) mit {chat.name}. Stimmt sie überein, ist kein
                  Man-in-the-Middle zwischen euch.
                </p>
                <QrLike data={chat.safetyNumber} />
                <div className="sn">{chat.safetyNumber}</div>
                <button className="btn" onClick={props.onToggleVerified}>
                  {chat.verified ? 'Verifizierung zurückziehen' : 'Als verifiziert markieren ✔'}
                </button>
              </>
            ) : (
              <>
                <p className="gate-info">
                  Gruppen-/Kanal-Fingerprint der aktuellen Schlüssel-Epoche. Bei jeder
                  Mitgliederänderung wird der Schlüssel automatisch rotiert (neue Epoche).
                </p>
                <div className="sn mono">Epoche {chat.epoch} · FP {chat.shortFp}</div>
                <button className="btn" onClick={props.onRotate}>Schlüssel jetzt rotieren ⟳</button>
              </>
            )}
            <button className="btn ghost" onClick={() => setModal(null)}>Schließen</button>
          </div>
        </div>
      )}

      {modal === 'members' && (
        <div className="modal-back" onClick={() => setModal(null)}>
          <div className="modal panel" onClick={(e) => e.stopPropagation()}>
            <h3>👥 Mitglieder — {chat.name}</h3>
            {chat.kind === 'channel' && (
              <p className="gate-info">
                Broadcast-Kanal · {chat.subscriberCount ?? 0} Abonnenten (read-only).
                Hier verwaltest du Owner/Admins.
              </p>
            )}
            {chat.members.map((m) => (
              <div key={m.id}>
                <div className="member-row">
                  <div className="avatar" style={{ width: 28, height: 28, fontSize: 11 }}>
                    {m.name.slice(0, 2).toUpperCase()}
                  </div>
                  <span>{m.name}{m.id === identity.userId ? ' (du)' : ''}</span>
                  <span className={`role ${m.role}`}>{m.role}</span>
                  {canRemove && m.id !== identity.userId && m.role !== 'owner' && (
                    <button className="btn dangerous tiny" onClick={() => props.onRemoveMember(m.id)}>
                      Entfernen
                    </button>
                  )}
                </div>
                {isOwner && m.role === 'admin' && (
                  <div className="perm-row">
                    {(['canPost', 'canInvite', 'canRemove', 'canPin'] as const).map((p) => (
                      <label key={p} className="perm-chip">
                        <input
                          type="checkbox"
                          checked={m.permissions?.[p] ?? true}
                          onChange={(e) => props.onSetPermission(m.id, { [p]: e.target.checked })}
                        />
                        {{ canPost: 'Senden', canInvite: 'Einladen', canRemove: 'Entfernen', canPin: 'Anheften' }[p]}
                      </label>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {canInvite && addable.length > 0 && (
              <>
                <h3 style={{ marginTop: 6 }}>Hinzufügen</h3>
                {addable.map((c) => (
                  <div className="member-row" key={c.id}>
                    <span>{c.name}</span>
                    <button className="btn" style={{ marginLeft: 'auto' }} onClick={() => props.onAddMember(c.id)}>
                      + Hinzufügen
                    </button>
                  </div>
                ))}
              </>
            )}
            <p className="gate-info tiny">
              ⟳ Jede Mitgliederänderung löst eine Schlüssel-Neuverteilung aus
              (neue Epoche) — Entfernte lesen nichts Späteres mehr mit.
            </p>
            <button className="btn ghost" onClick={() => setModal(null)}>Schließen</button>
          </div>
        </div>
      )}
    </main>
  );
}
