import { useState } from 'react';
import { RelayStatus } from '../net/client';
import { ARGON2 } from '../crypto/primitives';
import { DeviceInfo, Identity } from '../state/types';

const fmt = (ts: number) => new Date(ts).toLocaleString('de-DE');

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
    if (newPass.length < 8) return setPpMsg({ ok: false, text: 'Neue Passphrase: mindestens 8 Zeichen.' });
    if (newPass !== newPass2) return setPpMsg({ ok: false, text: 'Neue Passphrasen stimmen nicht überein.' });
    setPpBusy(true);
    try {
      const res = await props.onChangePassphrase(oldPass, newPass);
      if (res.ok) {
        setPpMsg({ ok: true, text: 'Passphrase geändert.' });
        setOldPass(''); setNewPass(''); setNewPass2('');
      } else {
        setPpMsg({ ok: false, text: res.reason === 'wrong-pass' ? 'Alte Passphrase falsch.' : 'Änderung fehlgeschlagen.' });
      }
    } finally {
      setPpBusy(false);
    }
  };

  return (
    <main className="main panel">
      <div className="page">
        <h2>⛨ Sicherheitszentrale</h2>

        <div className="card">
          <h4>Identität (ohne Telefonnummer)</h4>
          <div className="kv"><span className="k">Konto-ID</span><span className="v acc">{props.identity.userId}</span></div>
          <div className="kv"><span className="k">Anzeigename</span><span className="v">{props.identity.displayName}</span></div>
          <div className="kv"><span className="k">Signatur-Key (Ed25519)</span><span className="v tiny">{props.identity.edPub.slice(0, 24)}…</span></div>
          <div className="kv"><span className="k">DH-Key (X25519)</span><span className="v tiny">{props.identity.xPub.slice(0, 24)}…</span></div>
        </div>

        <div className="card">
          <h4>Geräte & aktive Sessions</h4>
          {props.devices.length === 0 && (
            <p className="dim tiny">
              Relay offline — nur dieses Gerät (lokaler Modus). Starte den Relay-Server,
              um Geräte kontenweit zu verwalten.
            </p>
          )}
          {props.devices.map((d) => (
            <div className="device-row" key={d.id}>
              <span className={`led ${d.online ? 'on' : 'off'}`} />
              <div style={{ flex: 1 }}>
                <div>
                  {d.name} {d.current && <span className="acc tiny">(dieses Gerät)</span>}{' '}
                  {!d.trusted && <span className="tiny" style={{ color: '#e8c33f' }}>⚠ unbestätigt</span>}
                </div>
                <div className="dim tiny mono">
                  hinzugefügt {fmt(d.createdAt)} · zuletzt {fmt(d.lastSeen)}
                </div>
              </div>
              {!d.trusted && (
                <button className="btn" onClick={() => props.onApprove(d.id)}>Bestätigen</button>
              )}
              {!d.current && (
                <button className="btn dangerous" onClick={() => props.onRevoke(d.id)}>Abmelden</button>
              )}
            </div>
          ))}
        </div>

        <div className="card">
          <h4>Lokale Datenbank (At-Rest-Verschlüsselung)</h4>
          <div className="kv"><span className="k">Verschlüsselung</span><span className="v">AES-256-GCM</span></div>
          <div className="kv"><span className="k">Schlüsselableitung</span><span className="v">Argon2id ({ARGON2.memorySizeKiB / 1024} MiB, t={ARGON2.iterations})</span></div>
          <div className="kv"><span className="k">Manipulationsschutz</span><span className="v">HMAC-SHA256 über Ciphertext</span></div>
          <div style={{ display: 'flex', gap: 10, marginTop: 12, alignItems: 'center' }}>
            <button className="btn" onClick={props.onCheckIntegrity}>Integrität jetzt prüfen</button>
            {props.integrityResult && (
              <span className={`mono tiny ${props.integrityResult === 'OK' ? 'acc' : ''}`}
                style={props.integrityResult !== 'OK' ? { color: 'var(--danger)' } : undefined}>
                Ergebnis: {props.integrityResult}
              </span>
            )}
          </div>
        </div>

        <div className="card">
          <h4>Schlüssel & Rotation</h4>
          <p className="dim tiny" style={{ lineHeight: 1.6 }}>
            1:1-Chats rotieren Schlüssel automatisch mit jeder Nachricht (Double
            Ratchet → Perfect Forward Secrecy). Gruppen/Kanäle nutzen Epoch-Keys,
            die bei Mitgliederänderungen und manuell rotiert werden.
          </p>
          <button className="btn" style={{ marginTop: 10 }} onClick={props.onRotateAll}>
            ⟳ Alle Gruppen-/Kanal-Schlüssel jetzt rotieren
          </button>
        </div>

        <div className="card">
          <h4>Passphrase ändern</h4>
          <p className="dim tiny" style={{ lineHeight: 1.6, marginBottom: 8 }}>
            Ändert nur die Passphrase, die den Tresor entsperrt — bestehende
            Kontakte, Sitzungen und Nachrichten bleiben unverändert erhalten.
          </p>
          <input className="input" type="password" placeholder="Aktuelle Passphrase"
            value={oldPass} onChange={(e) => setOldPass(e.target.value)} style={{ marginBottom: 8 }} />
          <input className="input" type="password" placeholder="Neue Passphrase (min. 8 Zeichen)"
            value={newPass} onChange={(e) => setNewPass(e.target.value)} style={{ marginBottom: 8 }} />
          <input className="input" type="password" placeholder="Neue Passphrase wiederholen"
            value={newPass2} onChange={(e) => setNewPass2(e.target.value)} style={{ marginBottom: 8 }} />
          <button className="btn" disabled={ppBusy || !oldPass || !newPass} onClick={submitPassphraseChange}>
            {ppBusy ? 'Ändere…' : 'Passphrase ändern'}
          </button>
          {ppMsg && (
            <div className="tiny" style={{ marginTop: 8, color: ppMsg.ok ? 'var(--acc)' : 'var(--danger)' }}>
              {ppMsg.ok ? '✓' : '✖'} {ppMsg.text}
            </div>
          )}
        </div>

        <div className="card">
          <h4>Notfall- / Duress-Modus</h4>
          <div className="kv">
            <span className="k">Status</span>
            <span className="v">{props.hasDuress ? 'aktiv — Notfall-PIN hinterlegt' : 'nicht eingerichtet'}</span>
          </div>
          <p className="dim tiny" style={{ marginTop: 8, lineHeight: 1.6 }}>
            Wird die Notfall-PIN statt der Passphrase eingegeben, öffnet sich eine
            leere Fake-Ansicht — der echte Tresor bleibt verschlossen und unsichtbar.
          </p>
        </div>
      </div>
    </main>
  );
}
