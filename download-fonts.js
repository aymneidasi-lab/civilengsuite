/**
 * Civil Engineering Suite — Font Downloader  v2
 * Run: node download-fonts.js
 * Output: creates public/fonts/ directory with all required woff2 files
 *
 * Fonts needed (matches @font-face declarations in both HTML files):
 *   Cairo:            400, 600, 700, 800  (Arabic + Latin)
 *   Inter:            400, 500, 600, 700
 *   Playfair Display: 400, 700, 900
 *   JetBrains Mono:   400, 600
 *
 * CHANGELOG v2 (2026-04-26):
 *   [F1] JetBrains Mono weight 600 added (was missing; @font-face references it).
 *   [F2] Playfair Display weight 900 added (was missing; @font-face references it).
 *   [F3] JetBrains Mono output filenames fixed:
 *        jetbrains-400.woff2  →  jetbrains-mono-400.woff2
 *        (new) jetbrains-600  →  jetbrains-mono-600.woff2
 *        These match the src:url('/fonts/jetbrains-mono-*.woff2') in @font-face.
 *   [F4] FONT_CSS_URLS updated to request wght@400;600 for JetBrains Mono
 *        and wght@400;700;900 for Playfair Display.
 */

const https = require('https');
const fs    = require('fs');
const path  = require('path');

const FONTS_DIR = path.join(__dirname, 'public', 'fonts');
if (!fs.existsSync(FONTS_DIR)) fs.mkdirSync(FONTS_DIR, { recursive: true });

// [F4] Fixed: JetBrains Mono now requests weight 400+600; Playfair requests 400+700+900
const FONT_CSS_URLS = [
  'https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap',
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap',
  'https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700;900&display=swap',
  'https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap',
];

// [F1][F2][F3] Weight map — output filenames match @font-face src urls in HTML
const WEIGHT_NAMES = {
  'Cairo':            { '400': 'cairo-400', '600': 'cairo-600', '700': 'cairo-700', '800': 'cairo-800' },
  'Inter':            { '400': 'inter-400', '500': 'inter-500', '600': 'inter-600', '700': 'inter-700' },
  'Playfair Display': { '400': 'playfair-400', '700': 'playfair-700', '900': 'playfair-900' },
  'JetBrains Mono':   { '400': 'jetbrains-mono-400', '600': 'jetbrains-mono-600' },
};

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36';

function fetchText(url) {
  return new Promise((res, rej) => {
    const opts = new URL(url);
    https.get({
      hostname: opts.hostname,
      path: opts.pathname + opts.search,
      headers: { 'User-Agent': USER_AGENT }
    }, (r) => {
      let d = '';
      r.on('data', c => d += c);
      r.on('end', () => res(d));
    }).on('error', rej);
  });
}

function downloadFile(url, dest) {
  return new Promise((res, rej) => {
    if (fs.existsSync(dest)) {
      console.log('  SKIP (exists):', path.basename(dest));
      return res();
    }
    const f = fs.createWriteStream(dest);
    https.get(url, { headers: { 'User-Agent': USER_AGENT } }, (r) => {
      r.pipe(f);
      f.on('finish', () => { f.close(); res(); });
    }).on('error', (e) => { fs.unlink(dest, () => {}); rej(e); });
  });
}

async function main() {
  console.log('Downloading fonts to', FONTS_DIR);
  console.log('Expected output files (' + (() => {
    let n = 0;
    for (const v of Object.values(WEIGHT_NAMES)) n += Object.keys(v).length;
    return n;
  })() + ' woff2 files):');
  for (const [family, weights] of Object.entries(WEIGHT_NAMES)) {
    for (const [w, name] of Object.entries(weights)) {
      console.log('  ' + name + '.woff2');
    }
  }
  console.log('');

  for (const cssUrl of FONT_CSS_URLS) {
    console.log('Fetching CSS:', cssUrl.replace('https://fonts.googleapis.com/css2?', '...'));
    const css = await fetchText(cssUrl);

    // Parse @font-face blocks
    const blocks = css.match(/@font-face\s*\{[^}]+\}/g) || [];
    for (const block of blocks) {
      const familyM = block.match(/font-family:\s*'?([^'";]+)/);
      const weightM = block.match(/font-weight:\s*(\d+)/);
      const srcM    = block.match(/src:[^;]*url\(([^)]+)\)[^;]*format\('woff2'\)/);
      if (!familyM || !weightM || !srcM) continue;

      const family   = familyM[1].trim();
      const weight   = weightM[1].trim();
      const woff2url = srcM[1].replace(/['"]/g, '');

      // Only download the latin/arabic subset (first block per weight usually)
      const nameMap = WEIGHT_NAMES[family];
      if (!nameMap || !nameMap[weight]) continue;

      const destFile = path.join(FONTS_DIR, nameMap[weight] + '.woff2');
      if (fs.existsSync(destFile)) {
        console.log('  SKIP (exists):', nameMap[weight] + '.woff2');
        continue;
      }
      console.log('  ' + family + ' ' + weight + ' → ' + nameMap[weight] + '.woff2');
      await downloadFile(woff2url, destFile);
    }
  }

  // ── Verify all expected files were created ───────────────────────────────
  console.log('\n── Verification ─────────────────────────────────────────');
  let allOk = true;
  for (const [family, weights] of Object.entries(WEIGHT_NAMES)) {
    for (const [w, name] of Object.entries(weights)) {
      const dest = path.join(FONTS_DIR, name + '.woff2');
      const exists = fs.existsSync(dest);
      const size   = exists ? (fs.statSync(dest).size / 1024).toFixed(1) + ' KB' : 'MISSING';
      console.log('  ' + (exists ? '✓' : '✗') + ' ' + name + '.woff2  ' + size);
      if (!exists) allOk = false;
    }
  }
  console.log('');
  if (allOk) {
    console.log('✅ All ' + (() => {
      let n = 0;
      for (const v of Object.values(WEIGHT_NAMES)) n += Object.keys(v).length;
      return n;
    })() + ' font files downloaded successfully.');
    console.log('');
    console.log('Next steps:');
    console.log('  1. Commit the public/fonts/ directory to your repo.');
    console.log('  2. Verify _headers has: /fonts/*  Cache-Control: public, max-age=31536000, immutable');
    console.log('  3. The HTML @font-face declarations already reference /fonts/*.woff2 paths.');
  } else {
    console.error('❌ Some fonts are missing. Check your network connection and retry.');
    process.exit(1);
  }
}

main().catch(console.error);
