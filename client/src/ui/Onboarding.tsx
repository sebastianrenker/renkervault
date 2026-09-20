import { useState } from 'react';
import { newUserId } from '../state/types';

export function CreateVault(props: {
  onCreate: (opts: { displayName: string; userId: string; passphrase: string; duressPin: string | null }) => void;
  busy: boolean;
}) {
  const [userId] = useState(newUserId());
  const [name, setName] = useState('');
  const [pass, setPass] = useState('');
  const [pass2, setPass2] = useState('');
  const [duress, setDuress] = useState('');
  const [err, setErr] = useState('');

  const submit = () => {
    if (pass.length < 8) return setErr('Passphrase: at least 8 characters.');
    if (pass !== pass2) return setErr('Passphrases do not match.');
    if (duress && duress === pass) return setErr('The duress PIN must not equal the passphrase.');
    setErr('');
    props.onCreate({
      displayName: name.trim() || 'Operator',
      userId,
      passphrase: pass,
      duressPin: duress || null,
    });
  };

  return (
    <div className="gate">
      <div className="gate-card panel">
        <div>
          <h1>🛡 Renker<b>Vault</b></h1>
          <div className="sub">RENKER INDUSTRIES — SECURE COMMS DIVISION</div>
        </div>
        <p className="gate-info">
          An account without a phone number, without email. Your identity is a locally
          generated ID + key pairs. The passphrase encrypts your
          local vault (Argon2id → AES-256-GCM) and never leaves this device.
        </p>
        <label>Your account ID (locally generated)</label>
        <div className="idbox">{userId}</div>
        <label>Display name</label>
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. S. Renker" />
        <label>Passphrase (min. 8 characters)</label>
        <input className="input" type="password" value={pass} onChange={(e) => setPass(e.target.value)} />
        <label>Repeat passphrase</label>
        <input className="input" type="password" value={pass2} onChange={(e) => setPass2(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submit()} />
        <label>Duress PIN (optional, opens a fake view)</label>
        <input className="input" type="password" value={duress} onChange={(e) => setDuress(e.target.value)} placeholder="empty = disabled" />
        {err && <div className="gate-err">✖ {err}</div>}
        <button className="btn solid" onClick={submit} disabled={props.busy}>
          {props.busy ? 'Generating keys…' : 'Create vault & generate keys'}
        </button>
      </div>
    </div>
  );
}

export function UnlockVault(props: {
  onUnlock: (passphrase: string) => void;
  busy: boolean;
  fails: number;
  lockedUntil: number;
  alarm: boolean;
  onReset: () => void;
  deviceMismatch?: boolean;
  kdfError?: boolean;
}) {
  const [pass, setPass] = useState('');
  const locked = props.lockedUntil > Date.now();

  return (
    <div className="gate">
      <div className="gate-card panel" style={props.alarm ? { borderColor: 'color-mix(in srgb, var(--danger) 50%, transparent)' } : undefined}>
        <div>
          <h1>🛡 Renker<b>Vault</b></h1>
          <div className="sub">RENKER INDUSTRIES — SECURE COMMS DIVISION</div>
        </div>
        <p className="gate-info">The vault is locked. Enter the passphrase to decrypt locally.</p>
        <label>Passphrase</label>
        <input
          className="input" type="password" value={pass} autoFocus
          disabled={locked || props.busy}
          onChange={(e) => setPass(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && pass) { props.onUnlock(pass); setPass(''); } }}
        />
        {props.deviceMismatch && (
          <div className="gate-err">
            🔒 This vault is bound to a different device/Windows account
            (hardware binding active) — the passphrase can be correct here
            and still not be enough.
          </div>
        )}
        {props.kdfError && (
          <div className="gate-err">
            ⚠ Key derivation failed — probably too little
            memory on this device. No sign of a wrong
            passphrase; simply try again or close other
            applications.
          </div>
        )}
        {props.fails > 0 && !locked && !props.deviceMismatch && !props.kdfError && (
          <div className="gate-err">✖ Wrong passphrase ({props.fails}/5 failed attempts)</div>
        )}
        {locked && (
          <div className="gate-err">
            🚨 LOCKOUT ACTIVE — too many failed attempts. Unlocks at {new Date(props.lockedUntil).toLocaleTimeString('en-GB')}.
          </div>
        )}
        <button
          className="btn solid"
          disabled={locked || props.busy || !pass}
          onClick={() => { props.onUnlock(pass); setPass(''); }}
        >
          {props.busy ? 'Checking (Argon2id)…' : 'Unlock'}
        </button>
        <button className="btn ghost tiny" onClick={props.onReset}>
          Irreversibly delete the vault & start over
        </button>
      </div>
    </div>
  );
}
