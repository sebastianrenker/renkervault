import { useState } from 'react';
import { Chat, Identity, Settings } from '../state/types';

function isInsecureRemoteRelay(url: string): boolean {
  try {
    const u = new URL(url);
    const isLocal = ['localhost', '127.0.0.1', '::1'].includes(u.hostname);
    return u.protocol === 'ws:' && !isLocal;
  } catch {
    return false;
  }
}

export function ContactsPage(props: {
  chats: Chat[];
  myUserId: string;
  onOpen: (chatId: string) => void;
  onToggleVerified: (chatId: string) => void;
  onAddContact: () => void;
}) {
  const directs = props.chats.filter((c) => c.kind === 'direct');
  return (
    <main className="main panel">
      <div className="page">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <h2 style={{ marginBottom: 0 }}>◉ Contacts</h2>
          <button className="btn solid" style={{ marginLeft: 'auto' }} onClick={props.onAddContact}>
            + Add a real contact
          </button>
        </div>
        <div className="card">
          <h4>Your account ID (share it so others can add you)</h4>
          <div className="idbox">{props.myUserId}</div>
        </div>
        {directs.map((c) => (
          <div className="card" key={c.id}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div className="avatar">{c.name.slice(0, 2).toUpperCase()}</div>
              <div style={{ flex: 1 }}>
                <div>
                  {c.name} {c.verified && <span className="vbadge">✔ verified</span>}{' '}
                  <span className="dim tiny">{c.origin === 'real' ? '· real contact' : '· demo'}</span>
                </div>
                <div className="dim tiny mono">
                  {c.origin === 'real' ? `${c.id} · ` : ''}FP {c.shortFp}
                </div>
              </div>
              <button className="btn" onClick={() => props.onToggleVerified(c.id)}>
                {c.verified ? 'Withdraw verification' : 'Mark as verified'}
              </button>
              <button className="btn ghost" onClick={() => props.onOpen(c.id)}>Open chat</button>
            </div>
          </div>
        ))}
        <p className="dim tiny">
          ⚠ If a contact's key changes (e.g. a reinstall), the
          verification is reset automatically and a warning is logged in the security log.
        </p>
      </div>
    </main>
  );
}

export function SettingsPage(props: {
  settings: Settings;
  identity: Identity;
  relayStatus: string;
  onToggle: (key: 'readReceipts' | 'typingIndicator' | 'alarmSound' | 'autoLockdown' | 'coverTraffic') => void;
  onSetRelayUrl: (url: string) => void;
  onDestroy: () => void;
}) {
  const rows: { key: 'readReceipts' | 'typingIndicator' | 'alarmSound' | 'autoLockdown' | 'coverTraffic'; label: string; desc: string }[] = [
    { key: 'readReceipts', label: 'Read receipts', desc: 'Off by default. Sends metadata ("read at…") to contacts — deliberately opt-in.' },
    { key: 'typingIndicator', label: 'Typing indicator', desc: 'Off by default. "typing…" is a metadata leak — deliberately opt-in.' },
    { key: 'coverTraffic', label: 'Cover traffic', desc: 'On by default. Sends invisible dummy messages to known contacts at irregular intervals, so that the relay can worse evaluate "who chats when and how often". Costs some battery/bandwidth even when idle.' },
    { key: 'alarmSound', label: 'Audible alarm', desc: 'A siren sound on security warnings (in addition to the red pulsing).' },
    { key: 'autoLockdown', label: 'Auto-lockdown', desc: 'On detected tampering of the local database, lock immediately and show only the alarm screen.' },
  ];
  const [relayInput, setRelayInput] = useState(props.settings.relayUrl);
  return (
    <main className="main panel">
      <div className="page">
        <h2>⚙ Settings</h2>
        <div className="card">
          <h4>Relay server</h4>
          <div className="kv">
            <span className="k">Status</span>
            <span className="v"><span className={`led ${props.relayStatus === 'online' ? 'on' : 'off'}`} /> {props.relayStatus.toUpperCase()}</span>
          </div>
          <label style={{ display: 'block', margin: '10px 0 4px' }}>Address (ws:// or wss://)</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input className="input" value={relayInput} onChange={(e) => setRelayInput(e.target.value)} placeholder="wss://my-relay.example.com" />
            <button className="btn" onClick={() => props.onSetRelayUrl(relayInput.trim())} disabled={!relayInput.trim()}>
              Apply
            </button>
          </div>
          {isInsecureRemoteRelay(relayInput) && (
            <div className="gate-err" style={{ marginTop: 8 }}>
              ⚠ "ws://" to a remote server is unencrypted transport
              (handshake/metadata visible in plaintext, e.g. to the network operator
              or an attacker on the same network). For anything other than{' '}
              <span className="mono">localhost</span>, be sure to use{' '}
              <span className="mono">wss://</span> with a valid TLS certificate
              — see deploy/DEPLOYMENT.md.
            </div>
          )}
          <p className="dim tiny" style={{ marginTop: 8, lineHeight: 1.6 }}>
            For chats with others, all participants must be able to reach the same relay
            — locally (<span className="mono">ws://localhost:8787</span>,
            only on this device), on the same network, or via a
            publicly reachable server (then use <span className="mono">wss://</span> with
            TLS, see SECURITY.md). A change rebuilds the
            connection.
          </p>
        </div>
        <div className="card">
          <h4>Privacy & alarm</h4>
          {rows.map((r) => (
            <div className="toggle-row" key={r.key}>
              <div>
                <div>{r.label}</div>
                <div className="d">{r.desc}</div>
              </div>
              <button
                className={`switch ${props.settings[r.key] ? 'on' : ''}`}
                onClick={() => props.onToggle(r.key)}
                aria-label={r.label}
              />
            </div>
          ))}
        </div>
        <div className="card">
          <h4>Backups</h4>
          <p className="dim tiny" style={{ lineHeight: 1.6 }}>
            RenkerVault creates NO plaintext cloud backups. The local vault is
            fully encrypted (Argon2id → AES-256-GCM); an export would only make sense
            as a client-side-encrypted file — the key stays with you.
          </p>
        </div>
        <div className="card">
          <h4>Danger zone</h4>
          <button className="btn dangerous" onClick={props.onDestroy}>
            Irreversibly delete the vault (all local data)
          </button>
        </div>
      </div>
    </main>
  );
}
