import { useEffect, useRef, useState } from 'react';
import { CallUiState } from './App';

function VideoTag(props: { stream: MediaStream | null; muted?: boolean; className: string }) {
  const ref = useRef<HTMLVideoElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.srcObject = props.stream;
  }, [props.stream]);
  return <video ref={ref} className={props.className} autoPlay playsInline muted={props.muted} />;
}

function useElapsed(active: boolean): string {
  const [n, setN] = useState(0);
  const startRef = useRef(Date.now());
  useEffect(() => {
    if (!active) { setN(0); return; }
    startRef.current = Date.now();
    const t = setInterval(() => setN(Math.floor((Date.now() - startRef.current) / 1000)), 1000);
    return () => clearInterval(t);
  }, [active]);
  const m = Math.floor(n / 60).toString().padStart(2, '0');
  const s = (n % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

export function CallOverlay(props: {
  call: CallUiState | null;
  onAccept: () => void;
  onDecline: () => void;
  onHangup: () => void;
  onToggleMute: () => void;
  onToggleCamera: () => void;
}) {
  const elapsed = useElapsed(props.call?.status === 'connected');
  if (!props.call) return null;
  const c = props.call;

  if (c.direction === 'in' && c.status === 'ringing') {
    return (
      <div className="call-incoming">
        <div className="call-incoming-card panel">
          <div className="call-avatar">{c.peerName.slice(0, 2).toUpperCase()}</div>
          <div className="call-peer-name">{c.peerName}</div>
          <div className="call-sub dim">{c.kind === 'video' ? '📹 Video-Anruf' : '📞 Sprachanruf'}</div>
          <div className="call-incoming-actions">
            <button className="btn dangerous call-round" onClick={props.onDecline}>✕</button>
            <button className="btn solid call-round" onClick={props.onAccept}>✓</button>
          </div>
        </div>
      </div>
    );
  }

  const statusText =
    c.status === 'connecting' && c.direction === 'out' ? 'Klingelt…' :
    c.status === 'connecting' ? 'Verbinde…' :
    c.status === 'connected' ? elapsed : 'Anruf';

  return (
    <div className="call-active">
      {c.kind === 'video' && c.remoteStream && c.remoteStream.getVideoTracks().length > 0 ? (
        <VideoTag stream={c.remoteStream} className="call-remote-video" />
      ) : (
        <div className="call-avatar call-avatar-big">{c.peerName.slice(0, 2).toUpperCase()}</div>
      )}
      <div className="call-hud">
        <div className="call-peer-name">{c.peerName}</div>
        <div className="call-sub dim">{statusText}</div>
      </div>
      {c.kind === 'video' && c.localStream && !c.cameraOff && (
        <VideoTag stream={c.localStream} muted className="call-local-video" />
      )}
      <div className="call-controls">
        <button className={`btn call-round ${c.muted ? 'active' : ''}`} onClick={props.onToggleMute} title={c.muted ? 'Ton an' : 'Stummschalten'}>
          {c.muted ? '🔇' : '🎤'}
        </button>
        {c.kind === 'video' && (
          <button className={`btn call-round ${c.cameraOff ? 'active' : ''}`} onClick={props.onToggleCamera} title={c.cameraOff ? 'Kamera an' : 'Kamera aus'}>
            {c.cameraOff ? '📷' : '📹'}
          </button>
        )}
        <button className="btn dangerous call-round" onClick={props.onHangup} title="Auflegen">📵</button>
      </div>
    </div>
  );
}
