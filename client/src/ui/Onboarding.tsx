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
    if (pass.length < 8) return setErr('Passphrase: mindestens 8 Zeichen.');
    if (pass !== pass2) return setErr('Passphrasen stimmen nicht überein.');
    if (duress && duress === pass) return setErr('Notfall-PIN darf nicht der Passphrase entsprechen.');
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
          Konto ohne Telefonnummer, ohne E-Mail. Deine Identität ist eine lokal
          erzeugte ID + Schlüsselpaare. Die Passphrase verschlüsselt deinen
          lokalen Tresor (Argon2id → AES-256-GCM) und verlässt dieses Gerät nie.
        </p>
        <label>Deine Konto-ID (lokal generiert)</label>
        <div className="idbox">{userId}</div>
        <label>Anzeigename</label>
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="z. B. S. Renker" />
        <label>Passphrase (min. 8 Zeichen)</label>
        <input className="input" type="password" value={pass} onChange={(e) => setPass(e.target.value)} />
        <label>Passphrase wiederholen</label>
        <input className="input" type="password" value={pass2} onChange={(e) => setPass2(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submit()} />
        <label>Notfall-PIN (optional, öffnet Fake-Ansicht)</label>
        <input className="input" type="password" value={duress} onChange={(e) => setDuress(e.target.value)} placeholder="leer = deaktiviert" />
        {err && <div className="gate-err">✖ {err}</div>}
        <button className="btn solid" onClick={submit} disabled={props.busy}>
          {props.busy ? 'Erzeuge Schlüssel…' : 'Tresor erstellen & Schlüssel erzeugen'}
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
        <p className="gate-info">Tresor ist gesperrt. Passphrase eingeben, um lokal zu entschlüsseln.</p>
        <label>Passphrase</label>
        <input
          className="input" type="password" value={pass} autoFocus
          disabled={locked || props.busy}
          onChange={(e) => setPass(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && pass) { props.onUnlock(pass); setPass(''); } }}
        />
        {props.fails > 0 && !locked && (
          <div className="gate-err">✖ Falsche Passphrase ({props.fails}/5 Fehlversuche)</div>
        )}
        {locked && (
          <div className="gate-err">
            🚨 LOCKOUT AKTIV — zu viele Fehlversuche. Freigabe {new Date(props.lockedUntil).toLocaleTimeString('de-DE')}.
          </div>
        )}
        <button
          className="btn solid"
          disabled={locked || props.busy || !pass}
          onClick={() => { props.onUnlock(pass); setPass(''); }}
        >
          {props.busy ? 'Prüfe (Argon2id)…' : 'Entsperren'}
        </button>
        <button className="btn ghost tiny" onClick={props.onReset}>
          Tresor unwiderruflich löschen & neu beginnen
        </button>
      </div>
    </div>
  );
}
