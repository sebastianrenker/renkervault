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
}) {
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
