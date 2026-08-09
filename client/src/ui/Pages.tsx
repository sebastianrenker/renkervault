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
          <h2 style={{ marginBottom: 0 }}>◉ Kontakte</h2>
          <button className="btn solid" style={{ marginLeft: 'auto' }} onClick={props.onAddContact}>
            + Echten Kontakt hinzufügen
          </button>
        </div>
        <div className="card">
          <h4>Deine Konto-ID (teile sie, damit andere dich hinzufügen können)</h4>
          <div className="idbox">{props.myUserId}</div>
        </div>
        {directs.map((c) => (
          <div className="card" key={c.id}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div className="avatar">{c.name.slice(0, 2).toUpperCase()}</div>
              <div style={{ flex: 1 }}>
                <div>
                  {c.name} {c.verified && <span className="vbadge">✔ verifiziert</span>}{' '}
                  <span className="dim tiny">{c.origin === 'real' ? '· echter Kontakt' : '· Demo'}</span>
                </div>
                <div className="dim tiny mono">
                  {c.origin === 'real' ? `${c.id} · ` : ''}FP {c.shortFp}
                </div>
              </div>
              <button className="btn" onClick={() => props.onToggleVerified(c.id)}>
                {c.verified ? 'Verifizierung zurückziehen' : 'Als verifiziert markieren'}
              </button>
              <button className="btn ghost" onClick={() => props.onOpen(c.id)}>Chat öffnen</button>
            </div>
          </div>
        ))}
        <p className="dim tiny">
          ⚠ Ändert sich der Schlüssel eines Kontakts (z. B. Neuinstallation), wird die
          Verifizierung automatisch zurückgesetzt und im Security-Log gewarnt.
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
    { key: 'readReceipts', label: 'Lesebestätigungen', desc: 'Standard AUS. Sendet Metadaten („gelesen um…") an Kontakte — bewusst opt-in.' },
    { key: 'typingIndicator', label: 'Tippindikator', desc: 'Standard AUS. „schreibt…" ist ein Metadaten-Leck — bewusst opt-in.' },
    { key: 'coverTraffic', label: 'Tarn-Traffic', desc: 'Standard AN. Sendet in unregelmäßigen Abständen unsichtbare Dummy-Nachrichten an bekannte Kontakte, damit der Relay „wer chattet wann wie oft" schlechter auswerten kann. Kostet etwas Akku/Bandbreite auch im Leerlauf.' },
    { key: 'alarmSound', label: 'Akustischer Alarm', desc: 'Sirenenton bei Sicherheitswarnungen (zusätzlich zum roten Pulsieren).' },
    { key: 'autoLockdown', label: 'Auto-Lockdown', desc: 'Bei erkannter Manipulation der lokalen Datenbank sofort sperren und nur den Alarm-Screen zeigen.' },
  ];
  const [relayInput, setRelayInput] = useState(props.settings.relayUrl);
  return (
    <main className="main panel">
      <div className="page">
        <h2>⚙ Einstellungen</h2>
        <div className="card">
          <h4>Relay-Server</h4>
          <div className="kv">
            <span className="k">Status</span>
            <span className="v"><span className={`led ${props.relayStatus === 'online' ? 'on' : 'off'}`} /> {props.relayStatus.toUpperCase()}</span>
          </div>
          <label style={{ display: 'block', margin: '10px 0 4px' }}>Adresse (ws:// oder wss://)</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input className="input" value={relayInput} onChange={(e) => setRelayInput(e.target.value)} placeholder="wss://mein-relay.beispiel.de" />
            <button className="btn" onClick={() => props.onSetRelayUrl(relayInput.trim())} disabled={!relayInput.trim()}>
              Übernehmen
            </button>
          </div>
          {isInsecureRemoteRelay(relayInput) && (
            <div className="gate-err" style={{ marginTop: 8 }}>
              ⚠ „ws://" zu einem entfernten Server ist unverschlüsselter Transport
              (Handshake/Metadaten im Klartext sichtbar, z. B. für den Netzbetreiber
              oder einen Angreifer im selben Netz). Für alles außer{' '}
              <span className="mono">localhost</span> unbedingt{' '}
              <span className="mono">wss://</span> mit gültigem TLS-Zertifikat
              verwenden — siehe deploy/DEPLOYMENT.md.
            </div>
          )}
          <p className="dim tiny" style={{ marginTop: 8, lineHeight: 1.6 }}>
            Für Chats mit anderen müssen alle Beteiligten denselben Relay
            erreichen können — lokal (<span className="mono">ws://localhost:8787</span>,
            nur auf diesem Gerät), im selben Netzwerk oder über einen
            öffentlich erreichbaren Server (dann <span className="mono">wss://</span> mit
            TLS verwenden, siehe SECURITY.md). Eine Änderung baut die
            Verbindung neu auf.
          </p>
        </div>
        <div className="card">
          <h4>Privatsphäre & Alarm</h4>
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
            RenkerVault legt KEINE Klartext-Cloud-Backups an. Der lokale Tresor ist
            vollständig verschlüsselt (Argon2id → AES-256-GCM); ein Export wäre nur
            als clientseitig verschlüsselte Datei sinnvoll — Schlüssel bleibt bei dir.
          </p>
        </div>
        <div className="card">
          <h4>Gefahrenzone</h4>
          <button className="btn dangerous" onClick={props.onDestroy}>
            Tresor unwiderruflich löschen (alle lokalen Daten)
          </button>
        </div>
      </div>
    </main>
  );
}
