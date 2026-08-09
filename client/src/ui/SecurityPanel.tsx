/** Rechtes Panel: "Security Log" — Live-Feed aller Sicherheitsereignisse
 *  plus Verbindungs-/Geräte-/Rotations-Status (statt Activity-Log). */
import { RelayStatus } from '../net/client';
import { SecEvent } from '../state/types';

const fmt = (ts: number) =>
  new Date(ts).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

export function SecurityPanel(props: {
  secLog: SecEvent[];
  relayStatus: RelayStatus;
  deviceCount: number;
  trustedCount: number;
  lastRotation: number;
  integrity: string;
}) {
  const relayLabel: Record<RelayStatus, [string, string]> = {
    online: ['on', 'ONLINE'],
    connecting: ['off', 'VERBINDE…'],
    offline: ['off', 'OFFLINE (LOKAL)'],
    locked: ['bad', 'GESPERRT'],
  };
  const [led, label] = relayLabel[props.relayStatus];
  const events = [...props.secLog].sort((a, b) => b.ts - a.ts).slice(0, 80);

  return (
    <aside className="seclog panel">
      <div className="seclog-head">
        <h3>◈ Security Log</h3>
      </div>
      <div className="seclog-stats">
        <div className="stat">
          <div className="k">Relay</div>
          <div className="v"><span className={`led ${led}`} /> {label}</div>
        </div>
        <div className="stat">
          <div className="k">Geräte</div>
          <div className="v">{props.trustedCount}/{props.deviceCount} vertraut</div>
        </div>
        <div className="stat">
          <div className="k">Letzte Rotation</div>
          <div className="v">{fmt(props.lastRotation)}</div>
        </div>
        <div className="stat">
          <div className="k">DB-Integrität</div>
          <div className="v">
            <span className={`led ${props.integrity === 'OK' ? 'on' : 'bad'}`} /> {props.integrity}
          </div>
        </div>
      </div>
      <div className="seclog-feed">
        {events.map((e) => (
          <div key={e.id} className={`ev ${e.severity}`}>
            <div className="t">
              <span>{fmt(e.ts)}{e.device ? ` · ${e.device}` : ''}</span>
              <span>{e.kind}</span>
            </div>
            <div className="x">{e.text}</div>
          </div>
        ))}
      </div>
    </aside>
  );
}
