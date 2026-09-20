#!/usr/bin/env node
/**
 * Generates SHA256SUMS.txt for all existing build artifacts (web build,
 * Tauri desktop bundle, Android APK). Does NOT replace a code signature — an
 * attacker who controls the distribution itself could tamper with both the
 * artifact and this file. The point is that someone who reproduces the build
 * themselves (see SECURITY.md section 4f/4g) can compare the resulting hash
 * against an independently published one (e.g. via a GPG-signed release note).
 *
 * Usage: node gen-checksums.mjs  (after `npm run build` /
 * `npx tauri build` / Android Gradle build, whichever is present)
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
      // A pattern with no match (build target not present) is not an error.
    }
  }

  if (files.length === 0) {
    console.error('No build artifacts found — run `npm run build` / `tauri build` / the Android build first.');
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
