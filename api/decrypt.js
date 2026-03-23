/**
 * Civil Engineering Suite — AES-256-GCM Decrypt
 * Node.js Serverless Function — reads .enc files from filesystem directly
 */

const fs   = require('fs');
const path = require('path');
const { createDecipheriv } = require('crypto');

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
    const authTag   = ciphertext.slice(ciphertext.length - 16);
    const encrypted = ciphertext.slice(0, ciphertext.length - 16);
    const decipher  = createDecipheriv('aes-256-gcm', keyBuf, nonce);
    decipher.setAuthTag(authTag);
    html = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf-8');
  } catch(e) {
    return res.status(500).send(page('Decrypt Error',
      `${e.message}<br>Check that CES_DECRYPT_KEY matches the key used to encrypt.`));
  }

  // ── 6. Multi-layer obfuscation wrapper ───────────────
  // Layer 1: base64 encode the full HTML
  const b64 = Buffer.from(html, 'utf-8').toString('base64');

  // Layer 2: split base64 into chunks and XOR each char code with a key
  const XOR_KEY = 0x5A;
  const xored = Buffer.from(b64, 'utf-8').map(c => c ^ XOR_KEY);
  const xoredB64 = xored.toString('base64');

  // Layer 3: split into random-length chunks to break pattern recognition
  const CHUNK = 76;
  const chunks = [];
  for (let i = 0; i < xoredB64.length; i += CHUNK) {
    chunks.push(JSON.stringify(xoredB64.slice(i, i + CHUNK)));
  }
  const chunkedStr = chunks.join(',');

  // Build the bootstrap page — view-source shows only this garbage
  const bootstrap = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0"><meta name="robots" content="noindex"><title>Loading...</title><style>*{margin:0;padding:0}body{background:#0A1A2E;display:flex;align-items:center;justify-content:center;min-height:100vh}.s{width:48px;height:48px;border:4px solid rgba(193,123,26,0.2);border-top-color:#C17B1A;border-radius:50%;animation:r 0.8s linear infinite}@keyframes r{to{transform:rotate(360deg)}}</style></head><body><div class="s"></div><script>!function(){try{var _0x1a=[${chunkedStr}];var _0x2b=_0x1a.join('');var _0x3c=atob(_0x2b);var _0x4d=new Uint8Array(_0x3c.length);for(var _0x5e=0;_0x5e<_0x3c.length;_0x5e++){_0x4d[_0x5e]=_0x3c.charCodeAt(_0x5e)^0x5A;}var _0x6f=new TextDecoder('utf-8').decode(_0x4d);var _0x7a=atob(_0x6f);var _0x8b=new Uint8Array(_0x7a.length);for(var _0x9c=0;_0x9c<_0x7a.length;_0x9c++){_0x8b[_0x9c]=_0x7a.charCodeAt(_0x9c);}var _0xad=new TextDecoder('utf-8').decode(_0x8b);var _0xbl=new Blob([_0xad],{type:'text/html;charset=utf-8'});var _0xur=URL.createObjectURL(_0xbl);location.replace(_0xur);}catch(_0xcf){document.body.innerHTML='<p style="color:#C17B1A;font-family:sans-serif;padding:40px">Loading failed. Please refresh.</p>';}}();</script></body></html>`;

  // ── 7. Serve ─────────────────────────────────────────
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.status(200).send(bootstrap);
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
