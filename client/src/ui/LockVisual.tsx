/** Zentrale Verschlüsselungs-Visualisierung (statt KI-Radar): rotierendes
 *  Schloss-/Schild-HUD mit Partikel-Kette; zeigt den aktiven E2E-Status. */

export function LockVisual(props: {
  fingerprint: string;
  caption: string;
  stats: { k: string; v: string }[];
}) {
  return (
    <div className="lockviz">
      <svg viewBox="0 0 240 240" fill="none" stroke="var(--accent)">
        {/* äußerer Segment-Ring */}
        <g className="ring-slow" opacity="0.65">
          {Array.from({ length: 24 }, (_, i) => {
            const a = (i / 24) * Math.PI * 2;
            const r1 = 108, r2 = i % 4 === 0 ? 96 : 102;
            return (
              <line
                key={i}
                x1={120 + r1 * Math.cos(a)} y1={120 + r1 * Math.sin(a)}
                x2={120 + r2 * Math.cos(a)} y2={120 + r2 * Math.sin(a)}
                strokeWidth={i % 4 === 0 ? 2 : 1}
              />
            );
          })}
          <circle cx="120" cy="120" r="112" strokeWidth="0.6" opacity="0.5" />
        </g>
        {/* Partikel-Kette (aktiver Chiffrier-Fluss) */}
        <circle
          className="chain-dash" cx="120" cy="120" r="86"
          strokeWidth="1.6" strokeDasharray="2 10" strokeLinecap="round" opacity="0.9"
        />
        <g className="ring-fast" opacity="0.5">
          <circle cx="120" cy="120" r="72" strokeWidth="1" strokeDasharray="40 18 8 18" />
        </g>
        {/* Schild */}
        <path
          d="M120 62 L165 80 V118 C165 150 146 172 120 184 C94 172 75 150 75 118 V80 Z"
          strokeWidth="2"
          fill="color-mix(in srgb, var(--accent) 7%, transparent)"
        />
        {/* Schloss im Schild */}
        <rect x="103" y="116" width="34" height="28" rx="4" strokeWidth="2"
          fill="color-mix(in srgb, var(--accent) 18%, transparent)" />
        <path d="M109 116 V106 a11 11 0 0 1 22 0 V116" strokeWidth="2" />
        <circle cx="120" cy="128" r="3.4" fill="var(--accent)" stroke="none" />
        <line x1="120" y1="131" x2="120" y2="138" strokeWidth="2.5" />
      </svg>
      <div className="cap">{props.caption}</div>
      <div className="fpbig">{props.fingerprint}</div>
      <div className="statrow">
        {props.stats.map((s) => (
          <span key={s.k}>{s.k} <b>{s.v}</b></span>
        ))}
      </div>
    </div>
  );
}
