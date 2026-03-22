/**
 * Civil Engineering Suite — AES-256-GCM Decrypt
 * Node.js Serverless Function — reads .enc files from filesystem directly
 * No HTTP fetching — no 401 issues
 */

const fs   = require('fs');
const path = require('path');
const { createDecipheriv, createHash } = require('crypto');

module.exports = async function handler(req, res) {

  // ── 1. Key ──────────────────────────────────────────
  const keyHex = (process.env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64) {
    return res.status(500).send(page('Configuration Error',
      'CES_DECRYPT_KEY is not set in Vercel Environment Variables.'));
  }

  let keyBuf;
  try { keyBuf = Buffer.from(keyHex, 'hex'); }
  catch(e) { return res.status(500).send(page('Key Error', e.message)); }

  // ── 2. Which file ────────────────────────────────────
  const url = req.url || '/';
  const pathname = url.split('?')[0].replace(/\/+$/, '') || '/';

  let encFile;
  if (pathname === '' || pathname === '/' || pathname === '/index.html') {
    encFile = 'pc_suite.enc';
  } else if (pathname.startsWith('/footing-pro')) {
    encFile = 'footing_pro.enc';
  } else {
    return res.status(404).send('Not found');
  }

  // ── 3. Read .enc file from filesystem ───────────────
  // process.cwd() = root of your repo on Vercel
  const encPath = path.join(process.cwd(), 'public', encFile);

  let encData;
  try {
    encData = fs.readFileSync(encPath, 'utf-8').trim();
  } catch(e) {
    return res.status(500).send(page('File Error',
      `Cannot read ${encFile}: ${e.message}<br>
       Path tried: ${encPath}<br>
       Files in public/: ${listDir(path.join(process.cwd(), 'public'))}`));
  }

  // ── 4. Parse nonce.ciphertext ────────────────────────
  const dot = encData.indexOf('.');
  if (dot === -1) {
    return res.status(500).send(page('Format Error', 'Invalid encrypted file format'));
  }

  let nonce, ciphertext;
  try {
    nonce      = Buffer.from(encData.slice(0, dot), 'base64');
    ciphertext = Buffer.from(encData.slice(dot + 1), 'base64');
  } catch(e) {
    return res.status(500).send(page('Parse Error', e.message));
  }

  // ── 5. Decrypt AES-256-GCM ───────────────────────────
  let html;
  try {
    // AES-GCM: last 16 bytes of ciphertext = auth tag
    const authTag    = ciphertext.slice(ciphertext.length - 16);
    const encrypted  = ciphertext.slice(0, ciphertext.length - 16);

    const decipher = createDecipheriv('aes-256-gcm', keyBuf, nonce);
    decipher.setAuthTag(authTag);

    html = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf-8');
  } catch(e) {
    return res.status(500).send(page('Decrypt Error',
      `${e.message}<br>Check that CES_DECRYPT_KEY matches the key used to encrypt.`));
  }

  // ── 6. Serve ─────────────────────────────────────────
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
  res.status(200).send(html);
};

function page(title, msg) {
  return `<!DOCTYPE html><html><head><title>${title}</title></head>
<body style="font-family:sans-serif;padding:40px">
<h2>${title}</h2><p>${msg}</p></body></html>`;
}

function listDir(dir) {
  try { return fs.readdirSync(dir).join(', '); }
  catch(e) { return `(cannot list: ${e.message})`; }
}
