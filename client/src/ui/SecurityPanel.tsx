import { RelayStatus } from '../net/client';
import { SecEvent } from '../state/types';

const fmt = (ts: number) =>
  new Date(ts).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

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
    connecting: ['off', 'CONNECTING…'],
    offline: ['off', 'OFFLINE (LOCAL)'],
    locked: ['bad', 'LOCKED'],
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
          <div className="k">Devices</div>
          <div className="v">{props.trustedCount}/{props.deviceCount} trusted</div>
        </div>
        <div className="stat">
          <div className="k">Last rotation</div>
          <div className="v">{fmt(props.lastRotation)}</div>
        </div>
        <div className="stat">
          <div className="k">DB integrity</div>
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
