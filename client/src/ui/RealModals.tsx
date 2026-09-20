import { useState } from 'react';
import { Contact } from '../state/types';

export function AddContactModal(props: {
  busy: boolean;
  error: string;
  onSubmit: (userId: string, name: string) => void;
  onClose: () => void;
}) {
  const [userId, setUserId] = useState('');
  const [name, setName] = useState('');
  return (
    <div className="modal-back" onClick={props.onClose}>
      <div className="modal panel" onClick={(e) => e.stopPropagation()}>
        <h3>◉ Add a real contact</h3>
        <p className="gate-info">
          Enter your counterpart's account ID (e.g. <span className="mono">RV-771F-11D3</span>).
          RenkerVault asks the relay for the public key and
          immediately establishes a real end-to-end session (X3DH-lite → Double
          Ratchet). Both sides must be connected to the same relay.
        </p>
        <label>Account ID</label>
        <input
          className="input mono" placeholder="RV-XXXX-XXXX" value={userId}
          onChange={(e) => setUserId(e.target.value.toUpperCase())}
          autoFocus
        />
        <label>Display name for this contact</label>
        <input className="input" placeholder="e.g. Nadja" value={name} onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && userId && props.onSubmit(userId.trim(), name.trim())} />
        {props.error && <div className="gate-err">✖ {props.error}</div>}
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className="btn solid" disabled={props.busy || !userId.trim()}
            onClick={() => props.onSubmit(userId.trim(), name.trim())}
          >
            {props.busy ? 'Searching the relay…' : 'Find contact & connect'}
          </button>
          <button className="btn ghost" onClick={props.onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

export function CreateGroupModal(props: {
  contacts: Contact[];
  busy: boolean;
  error: string;
  onSubmit: (name: string, memberIds: string[]) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const toggle = (id: string) => {
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  return (
    <div className="modal-back" onClick={props.onClose}>
      <div className="modal panel" onClick={(e) => e.stopPropagation()}>
        <h3>⬡ Create a real group</h3>
        <label>Group name</label>
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        <p className="gate-info tiny">
          The group key is distributed to each selected member individually over
          your existing 1:1 session (sender-keys-lite). Only
          already-added contacts can be invited.
        </p>
        {props.contacts.length === 0 ? (
          <p className="dim tiny">
            No real contacts yet. First add someone via "Contacts" →
            "Add contact".
          </p>
        ) : (
          props.contacts.map((c) => (
            <div className="member-row" key={c.userId}>
              <div className="avatar" style={{ width: 28, height: 28, fontSize: 11 }}>
                {c.name.slice(0, 2).toUpperCase()}
              </div>
              <span>{c.name}</span>
              <button
                className={`btn ${selected.has(c.userId) ? 'solid' : 'ghost'}`}
                style={{ marginLeft: 'auto' }}
                onClick={() => toggle(c.userId)}
              >
                {selected.has(c.userId) ? '✔ Selected' : 'Invite'}
              </button>
            </div>
          ))
        )}
        {props.error && <div className="gate-err">✖ {props.error}</div>}
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className="btn solid" disabled={props.busy || !name.trim() || selected.size === 0}
            onClick={() => props.onSubmit(name.trim(), [...selected])}
          >
            {props.busy ? 'Generating group key…' : `Create group (${selected.size} invited)`}
          </button>
          <button className="btn ghost" onClick={props.onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}
