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
    return res.status(500).send(errPage('Configuration Error',
      'CES_DECRYPT_KEY is not set in Vercel Environment Variables.'));
  }

  let keyBuf;
  try { keyBuf = Buffer.from(keyHex, 'hex'); }
  catch(e) { return res.status(500).send(errPage('Key Error', e.message)); }

  // ── 2. Which file ────────────────────────────────────
  const url      = req.url || '/';
  const pathname = url.split('?')[0].replace(/\/+$/, '') || '/';

  let encFile, baseHref;
  if (pathname === '' || pathname === '/' || pathname === '/index.html') {
    encFile  = 'pc_suite.enc';
    baseHref = '/';
  } else if (pathname.startsWith('/footing-pro')) {
    encFile  = 'footing_pro.enc';
    baseHref = '/footing-pro/';
  } else {
    return res.status(404).send('Not found');
  }

  // ── 3. Read .enc file ───────────────────────────────
  const encPath = path.join(process.cwd(), 'public', encFile);
  let encData;
  try {
    encData = fs.readFileSync(encPath, 'utf-8').trim();
  } catch(e) {
    return res.status(500).send(errPage('File Error',
      `Cannot read ${encFile}: ${e.message}<br>
       Path tried: ${encPath}<br>
       Files in public/: ${listDir(path.join(process.cwd(), 'public'))}`));
  }

  // ── 4. Parse nonce.ciphertext ────────────────────────
  const dot = encData.indexOf('.');
  if (dot === -1)
    return res.status(500).send(errPage('Format Error', 'Invalid encrypted file format'));

  let nonce, ciphertext;
  try {
    nonce      = Buffer.from(encData.slice(0, dot), 'base64');
    ciphertext = Buffer.from(encData.slice(dot + 1), 'base64');
  } catch(e) {
    return res.status(500).send(errPage('Parse Error', e.message));
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
    return res.status(500).send(errPage('Decrypt Error',
      `${e.message}<br>Check that CES_DECRYPT_KEY matches the key used to encrypt.`));
  }

  // ── 6. Inject <base> tag so all relative paths resolve correctly ──
  // This fixes images, links, and favicons for both / and /footing-pro/
  html = html.replace(/(<head[^>]*>)/i,
    `$1<base href="${baseHref}">`);

  // ── 7. Multi-layer obfuscation ───────────────────────
  // Layer 1: base64 encode full HTML
  const b64 = Buffer.from(html, 'utf-8').toString('base64');

  // Layer 2: XOR every byte
  const XOR_KEY  = 0x5A;
  const xored    = Buffer.from(b64, 'utf-8').map(c => c ^ XOR_KEY);
  const xoredB64 = xored.toString('base64');

  // Layer 3: split into 9000+ chunks
  const CHUNK = 76;
  const chunks = [];
  for (let i = 0; i < xoredB64.length; i += CHUNK)
    chunks.push(JSON.stringify(xoredB64.slice(i, i + CHUNK)));
  const chunkedStr = chunks.join(',');

  // ── 8. Bootstrap page ────────────────────────────────
  // The spinner style is SCOPED to #_ces_sp so it cannot leak into the decoded page.
  // document.open() fully resets the document before writing.
  const bootstrap = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0"><meta name="robots" content="noindex"><title>Loading\u2026</title><style>#_ces_sp{position:fixed;inset:0;background:#0A1A2E;display:flex;align-items:center;justify-content:center;z-index:999999}#_ces_sp div{width:48px;height:48px;border:4px solid rgba(193,123,26,0.2);border-top-color:#C17B1A;border-radius:50%;animation:_ces_r 0.8s linear infinite}@keyframes _ces_r{to{transform:rotate(360deg)}}</style></head><body><div id="_ces_sp"><div></div></div><script>!function(){try{var _a=[${chunkedStr}];var _b=_a.join('');var _c=atob(_b);var _d=new Uint8Array(_c.length);for(var _e=0;_e<_c.length;_e++){_d[_e]=_c.charCodeAt(_e)^0x5A;}var _f=new TextDecoder('utf-8').decode(_d);var _g=atob(_f);var _h=new Uint8Array(_g.length);for(var _i=0;_i<_g.length;_i++){_h[_i]=_g.charCodeAt(_i);}var _j=new TextDecoder('utf-8').decode(_h);var _k=document.open('text/html','replace');_k.write(_j);_k.close();}catch(_l){document.body.innerHTML='<p style="color:#C17B1A;font-family:sans-serif;padding:40px">Loading failed \u2014 please refresh.</p>';}}();<\/script></body></html>`;

  // ── 9. Serve ─────────────────────────────────────────
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.status(200).send(bootstrap);
};

function errPage(title, msg) {
  return `<!DOCTYPE html><html><head><title>${title}</title></head>
<body style="font-family:sans-serif;padding:40px"><h2>${title}</h2><p>${msg}</p></body></html>`;
}

function listDir(dir) {
  try { return fs.readdirSync(dir).join(', '); }
  catch(e) { return `(cannot list: ${e.message})`; }
}
