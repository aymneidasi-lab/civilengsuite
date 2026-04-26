const sharp = require('sharp');
const fs    = require('fs');
const path  = require('path');

const SCAN_DIRS = [
  'public/images',
  'public/footing-pro/images',
  'public/beam-pro/images',
  'public/column-pro/images',
  'public/deflection-pro/images',
  'public/earthquake-pro/images',
  'public/mur-pro/images',
  'public/add-reft-pro/images',
  'public/section-property-pro/images',
];

const WEBP_QUALITY = 82;
const AVIF_QUALITY = 65;

function collectImages(dirs) {
  const files = [];
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) continue;
    for (const file of fs.readdirSync(dir)) {
      if (/\.(png|jpg|jpeg)$/i.test(file)) {
        files.push(path.join(dir, file));
      }
    }
  }
  return files;
}

async function convert(src) {
  const base = src.replace(/\.(png|jpg|jpeg)$/i, '');
  const name = path.basename(src);

  // WebP
  const webp = base + '.webp';
  if (!fs.existsSync(webp)) {
    try {
      await sharp(src).webp({ quality: WEBP_QUALITY }).toFile(webp);
      const pct = Math.round((1 - fs.statSync(webp).size / fs.statSync(src).size) * 100);
      console.log(`  ✓ ${name} → .webp  (${pct}% smaller)`);
    } catch (e) {
      console.log(`  ✗ ${name} → .webp  SKIPPED — corrupted file (${e.message})`);
    }
  } else {
    console.log(`  – ${name} → .webp  (already exists)`);
  }

  // AVIF
  const avif = base + '.avif';
  if (!fs.existsSync(avif)) {
    try {
      await sharp(src).avif({ quality: AVIF_QUALITY }).toFile(avif);
      const pct = Math.round((1 - fs.statSync(avif).size / fs.statSync(src).size) * 100);
      console.log(`  ✓ ${name} → .avif  (${pct}% smaller)`);
    } catch (e) {
      console.log(`  ✗ ${name} → .avif  SKIPPED — corrupted file (${e.message})`);
    }
  } else {
    console.log(`  – ${name} → .avif  (already exists)`);
  }
}

async function main() {
  const images = collectImages(SCAN_DIRS);
  if (images.length === 0) {
    console.log('No images found. Make sure you run this from your repo root folder.');
    return;
  }
  console.log(`Found ${images.length} images. Converting...\n`);
  for (const img of images) await convert(img);
  console.log('\n✅ Done!');
  console.log('\nNow commit to GitHub:');
  console.log('  git add public/');
  console.log('  git commit -m "feat: add WebP and AVIF image variants"');
  console.log('  git push');
}

main().catch(console.error);
