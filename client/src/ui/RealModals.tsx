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
        <h3>◉ Echten Kontakt hinzufügen</h3>
        <p className="gate-info">
          Gib die Konto-ID deines Gegenübers ein (z. B. <span className="mono">RV-771F-11D3</span>).
          RenkerVault fragt den Relay nach dem öffentlichen Schlüssel und
          baut sofort eine echte Ende-zu-Ende-Sitzung auf (X3DH-lite → Double
          Ratchet). Beide Seiten müssen mit demselben Relay verbunden sein.
        </p>
        <label>Konto-ID</label>
        <input
          className="input mono" placeholder="RV-XXXX-XXXX" value={userId}
          onChange={(e) => setUserId(e.target.value.toUpperCase())}
          autoFocus
        />
        <label>Anzeigename für diesen Kontakt</label>
        <input className="input" placeholder="z. B. Nadja" value={name} onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && userId && props.onSubmit(userId.trim(), name.trim())} />
        {props.error && <div className="gate-err">✖ {props.error}</div>}
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className="btn solid" disabled={props.busy || !userId.trim()}
            onClick={() => props.onSubmit(userId.trim(), name.trim())}
          >
            {props.busy ? 'Suche im Relay…' : 'Kontakt suchen & verbinden'}
          </button>
          <button className="btn ghost" onClick={props.onClose}>Abbrechen</button>
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
        <h3>⬡ Echte Gruppe erstellen</h3>
        <label>Gruppenname</label>
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        <p className="gate-info tiny">
          Der Gruppenschlüssel wird für jedes ausgewählte Mitglied einzeln über
          eure bestehende 1:1-Sitzung verteilt (Sender-Keys-lite). Es können
          nur bereits hinzugefügte Kontakte eingeladen werden.
        </p>
        {props.contacts.length === 0 ? (
          <p className="dim tiny">
            Noch keine echten Kontakte vorhanden. Füge zuerst über „Kontakte" →
            „Kontakt hinzufügen" jemanden hinzu.
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
                {selected.has(c.userId) ? '✔ Ausgewählt' : 'Einladen'}
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
            {props.busy ? 'Erzeuge Gruppenschlüssel…' : `Gruppe erstellen (${selected.size} eingeladen)`}
          </button>
          <button className="btn ghost" onClick={props.onClose}>Abbrechen</button>
        </div>
      </div>
    </div>
  );
}
