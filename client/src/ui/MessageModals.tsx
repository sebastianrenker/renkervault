import { Chat, Message } from '../state/types';

export function ForwardModal(props: {
  message: Message;
  chats: Chat[];
  onForward: (chatId: string) => void;
  onClose: () => void;
}) {
  const targets = props.chats.filter((c) => c.kind !== 'channel' || c.origin === 'demo');
  return (
    <div className="modal-back" onClick={props.onClose}>
      <div className="modal panel" onClick={(e) => e.stopPropagation()}>
        <h3>➦ Nachricht weiterleiten</h3>
        <div className="card" style={{ marginBottom: 4 }}>
          <div className="dim tiny">{props.message.fromName}</div>
          <div>{props.message.kind === 'file' ? `📎 ${props.message.fileName}` : props.message.body.slice(0, 160)}</div>
        </div>
        {targets.map((c) => (
          <div className="member-row" key={c.id}>
            <div className={`avatar ${c.kind}`} style={{ width: 28, height: 28, fontSize: 11 }}>
              {c.kind === 'group' ? '⬡' : c.name.slice(0, 2).toUpperCase()}
            </div>
            <span>{c.name}</span>
            <button className="btn" style={{ marginLeft: 'auto' }} onClick={() => props.onForward(c.id)}>
              Weiterleiten
            </button>
          </div>
        ))}
        {targets.length === 0 && <p className="dim tiny">Keine Ziel-Chats verfügbar.</p>}
        <button className="btn ghost" onClick={props.onClose}>Abbrechen</button>
      </div>
    </div>
  );
}
