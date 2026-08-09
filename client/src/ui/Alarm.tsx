import { AlarmState } from '../state/types';

export function AlarmOverlay(props: {
  alarm: AlarmState;
  onAck: () => void;
  onLock: () => void;
}) {
  const { alarm } = props;
  if (!alarm.active) return null;
  return (
    <>
      <div className="alarm-vignette" />
      <div className="alarm-banner" role="alert">
        <span className="siren">🚨</span>
        <div className="txt">
          <b>SICHERHEITSWARNUNG — unautorisierter Zugriffsversuch erkannt</b>
          <div>
            {alarm.kind} · {alarm.reason} · {new Date(alarm.ts).toLocaleTimeString('de-DE')}
          </div>
        </div>
        <button className="btn" onClick={props.onAck}>Alarm quittieren</button>
        <button className="btn" onClick={props.onLock}>Sofort sperren</button>
      </div>
    </>
  );
}
