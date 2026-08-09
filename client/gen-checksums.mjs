#!/usr/bin/env node
/**
 * Erzeugt SHA256SUMS.txt fuer alle vorhandenen Build-Artefakte (Web-Build,
 * Tauri-Desktop-Bundle, Android-APK). Ersetzt KEINE Code-Signatur — ein
 * Angreifer, der die Auslieferung selbst kontrolliert, koennte sowohl das
 * Artefakt als auch diese Datei manipulieren. Der Sinn liegt darin, dass
 * jemand, der den Build selbst reproduziert (siehe SECURITY.md Abschnitt 4f/4g),
 * den resultierenden Hash gegen einen unabhaengig veroeffentlichten
 * (z. B. per GPG-signierter Release-Notiz) vergleichen kann.
 *
 * Verwendung: node gen-checksums.mjs  (nach `npm run build` /
 * `npx tauri build` / Android-Gradle-Build, je nachdem was vorhanden ist)
 */
import { createHash } from 'node:crypto';
import { createReadStream, existsSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { globSync } from 'node:fs';

const ROOT = import.meta.dirname;

const CANDIDATE_GLOBS = [
  'dist/**/*',
  'src-tauri/target/release/bundle/**/*.{msi,exe,dmg,app,deb,rpm,AppImage}',
  'android/app/build/outputs/apk/**/*.apk',
  'android/app/build/outputs/bundle/**/*.aab',
];

function sha256File(path) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(path);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

async function main() {
  const files = [];
  for (const pattern of CANDIDATE_GLOBS) {
    try {
      for (const p of globSync(pattern, { cwd: ROOT })) {
        const full = join(ROOT, p);
        if (existsSync(full) && statSync(full).isFile()) files.push(full);
      }
    } catch {
      // Muster ohne Treffer (Build-Ziel nicht vorhanden) ist kein Fehler.
    }
  }

  if (files.length === 0) {
    console.error('Keine Build-Artefakte gefunden — erst `npm run build` / `tauri build` / Android-Build ausfuehren.');
    process.exit(1);
  }

  const lines = [];
  for (const f of files.sort()) {
    const hash = await sha256File(f);
    lines.push(`${hash}  ${relative(ROOT, f).split('\\').join('/')}`);
  }

  const out = join(ROOT, 'SHA256SUMS.txt');
  writeFileSync(out, lines.join('\n') + '\n', 'utf8');
  console.log(`${lines.length} Artefakt(e) gehasht -> ${out}`);
  for (const l of lines) console.log('  ' + l);
}

main();
