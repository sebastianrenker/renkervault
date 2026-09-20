import { useState } from 'react';
import { RelayStatus } from '../net/client';
import { ARGON2 } from '../crypto/primitives';
import { DeviceInfo, Identity } from '../state/types';

const fmt = (ts: number) => new Date(ts).toLocaleString('en-GB');

export function SecurityCenter(props: {
  identity: Identity;
  devices: DeviceInfo[];
  relayStatus: RelayStatus;
  hasDuress: boolean;
  integrityResult: string | null;
  onApprove: (id: string) => void;
  onRevoke: (id: string) => void;
  onCheckIntegrity: () => void;
  onRotateAll: () => void;
  onChangePassphrase: (oldPass: string, newPass: string) => Promise<{ ok: boolean; reason?: string }>;
}) {
  const [oldPass, setOldPass] = useState('');
  const [newPass, setNewPass] = useState('');
  const [newPass2, setNewPass2] = useState('');
  const [ppMsg, setPpMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [ppBusy, setPpBusy] = useState(false);

  const submitPassphraseChange = async () => {
    setPpMsg(null);
    if (newPass.length < 8) return setPpMsg({ ok: false, text: 'New passphrase: at least 8 characters.' });
    if (newPass !== newPass2) return setPpMsg({ ok: false, text: 'New passphrases do not match.' });
    setPpBusy(true);
    try {
      const res = await props.onChangePassphrase(oldPass, newPass);
      if (res.ok) {
        setPpMsg({ ok: true, text: 'Passphrase changed.' });
        setOldPass(''); setNewPass(''); setNewPass2('');
      } else {
        setPpMsg({ ok: false, text: res.reason === 'wrong-pass' ? 'Old passphrase is wrong.' : 'Change failed.' });
      }
    } finally {
      setPpBusy(false);
    }
  };

  return (
    <main className="main panel">
      <div className="page">
        <h2>⛨ Security center</h2>

        <div className="card">
          <h4>Identity (without a phone number)</h4>
          <div className="kv"><span className="k">Account ID</span><span className="v acc">{props.identity.userId}</span></div>
          <div className="kv"><span className="k">Display name</span><span className="v">{props.identity.displayName}</span></div>
          <div className="kv"><span className="k">Signature key (Ed25519)</span><span className="v tiny">{props.identity.edPub.slice(0, 24)}…</span></div>
          <div className="kv"><span className="k">DH key (X25519)</span><span className="v tiny">{props.identity.xPub.slice(0, 24)}…</span></div>
        </div>

        <div className="card">
          <h4>Devices & active sessions</h4>
          {props.devices.length === 0 && (
            <p className="dim tiny">
              Relay offline — only this device (local mode). Start the relay server
              to manage devices account-wide.
            </p>
          )}
          {props.devices.map((d) => (
            <div className="device-row" key={d.id}>
              <span className={`led ${d.online ? 'on' : 'off'}`} />
              <div style={{ flex: 1 }}>
                <div>
                  {d.name} {d.current && <span className="acc tiny">(this device)</span>}{' '}
                  {!d.trusted && <span className="tiny" style={{ color: '#e8c33f' }}>⚠ unconfirmed</span>}
                </div>
                <div className="dim tiny mono">
                  added {fmt(d.createdAt)} · last {fmt(d.lastSeen)}
                </div>
              </div>
              {!d.trusted && (
                <button className="btn" onClick={() => props.onApprove(d.id)}>Confirm</button>
              )}
              {!d.current && (
                <button className="btn dangerous" onClick={() => props.onRevoke(d.id)}>Sign out</button>
              )}
            </div>
          ))}
        </div>

        <div className="card">
          <h4>Local database (at-rest encryption)</h4>
          <div className="kv"><span className="k">Encryption</span><span className="v">AES-256-GCM</span></div>
          <div className="kv"><span className="k">Key derivation</span><span className="v">Argon2id ({ARGON2.memorySizeKiB / 1024} MiB, t={ARGON2.iterations})</span></div>
          <div className="kv"><span className="k">Tamper protection</span><span className="v">HMAC-SHA256 over ciphertext</span></div>
          <div style={{ display: 'flex', gap: 10, marginTop: 12, alignItems: 'center' }}>
            <button className="btn" onClick={props.onCheckIntegrity}>Check integrity now</button>
            {props.integrityResult && (
              <span className={`mono tiny ${props.integrityResult === 'OK' ? 'acc' : ''}`}
                style={props.integrityResult !== 'OK' ? { color: 'var(--danger)' } : undefined}>
                Result: {props.integrityResult}
              </span>
            )}
          </div>
        </div>

        <div className="card">
          <h4>Keys & rotation</h4>
          <p className="dim tiny" style={{ lineHeight: 1.6 }}>
            1:1 chats rotate keys automatically with every message (Double
            Ratchet → perfect forward secrecy). Groups/channels use epoch keys,
            rotated on member changes and manually.
          </p>
          <button className="btn" style={{ marginTop: 10 }} onClick={props.onRotateAll}>
            ⟳ Rotate all group/channel keys now
          </button>
        </div>

        <div className="card">
          <h4>Change passphrase</h4>
          <p className="dim tiny" style={{ lineHeight: 1.6, marginBottom: 8 }}>
            Changes only the passphrase that unlocks the vault — existing
            contacts, sessions, and messages are kept unchanged.
          </p>
          <input className="input" type="password" placeholder="Current passphrase"
            value={oldPass} onChange={(e) => setOldPass(e.target.value)} style={{ marginBottom: 8 }} />
          <input className="input" type="password" placeholder="New passphrase (min. 8 characters)"
            value={newPass} onChange={(e) => setNewPass(e.target.value)} style={{ marginBottom: 8 }} />
          <input className="input" type="password" placeholder="Repeat new passphrase"
            value={newPass2} onChange={(e) => setNewPass2(e.target.value)} style={{ marginBottom: 8 }} />
          <button className="btn" disabled={ppBusy || !oldPass || !newPass} onClick={submitPassphraseChange}>
            {ppBusy ? 'Changing…' : 'Change passphrase'}
          </button>
          {ppMsg && (
            <div className="tiny" style={{ marginTop: 8, color: ppMsg.ok ? 'var(--acc)' : 'var(--danger)' }}>
              {ppMsg.ok ? '✓' : '✖'} {ppMsg.text}
            </div>
          )}
        </div>

        <div className="card">
          <h4>Emergency / duress mode</h4>
          <div className="kv">
            <span className="k">Status</span>
            <span className="v">{props.hasDuress ? 'active — duress PIN configured' : 'not set up'}</span>
          </div>
          <p className="dim tiny" style={{ marginTop: 8, lineHeight: 1.6 }}>
            If the duress PIN is entered instead of the passphrase, an
            empty fake view opens — the real vault stays locked and invisible.
          </p>
        </div>
      </div>
    </main>
  );
}
