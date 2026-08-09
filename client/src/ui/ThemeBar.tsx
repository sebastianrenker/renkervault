/** Untere Leiste: Theme-Presets + Akzentfarben (wie im Referenz-Dashboard,
 *  aber mit eigener Palette) + Dev-Bereich zum Simulieren von Angriffen. */
import { ACCENTS, Settings, THEMES, ThemeName } from '../state/types';

export function ThemeBar(props: {
  settings: Settings;
  onTheme: (t: ThemeName) => void;
  onAccent: (c: string) => void;
  onSimIntrusion: () => void;
  onSimTamper: () => void;
}) {
  const { settings } = props;
  return (
    <div className="dock panel">
      <span className="lbl">Theme</span>
      {THEMES.map((t) => (
        <button
          key={t.id}
          className={`preset ${settings.theme === t.id ? 'active' : ''}`}
          onClick={() => props.onTheme(t.id)}
        >
          {t.label}
        </button>
      ))}
      <span className="lbl" style={{ marginLeft: 10 }}>Akzent</span>
      {ACCENTS.map((c) => (
        <button
          key={c}
          className={`swatch ${settings.accent === c ? 'active' : ''}`}
          style={{ background: c, color: c }}
          onClick={() => props.onAccent(c)}
          title={c}
        />
      ))}
      <div className="dev">
        <span className="lbl">Dev</span>
        <button className="btn dangerous" onClick={props.onSimIntrusion}>
          ⚠ Intrusion simulieren
        </button>
        <button className="btn dangerous" onClick={props.onSimTamper}>
          DB-Manipulation simulieren
        </button>
      </div>
    </div>
  );
}
