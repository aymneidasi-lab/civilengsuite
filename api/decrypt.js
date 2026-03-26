/**
 * Civil Engineering Suite — AES-256-GCM Decrypt
 */

const fs   = require('fs');
const path = require('path');
const { createDecipheriv, randomBytes } = require('crypto');

// No bot detection needed here — Vercel's rewrite rules (missing: user-agent)
// prevent bots from ever reaching /api/decrypt. Bots are served the static
// index.html landing page directly by Vercel's file system routing instead.
// This eliminates the cloaking risk (serving different content to Googlebot
// vs real users) and ensures Google never indexes the decrypted app logic.

module.exports = async function handler(req, res) {

  const keyHex = (process.env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64)
    return res.status(500).send(errPage('Server Error', 'Internal configuration error.'));

  let keyBuf;
  try { keyBuf = Buffer.from(keyHex, 'hex'); }
  catch(e) { return res.status(500).send(errPage('Server Error', 'Internal configuration error.')); }

  const pathname = (req.url||'/').split('?')[0].replace(/\/+$/,'') || '/';

  let encFile, baseHref, faviconLinks, pageFilename;
  if (pathname === '' || pathname === '/' || pathname === '/index.html') {
    encFile      = 'pc_suite.enc';
    baseHref     = '/';
    pageFilename = 'civil-engineering-suite.html';
    faviconLinks = '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                 + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">';
  } else if (pathname.startsWith('/footing-pro')) {
    encFile      = 'footing_pro.enc';
    baseHref     = '/footing-pro/';
    pageFilename = 'footing-pro.html';
    faviconLinks = '<link rel="icon" type="image/png" sizes="32x32" href="/footing-pro/images/favicon-32.png">'
                 + '<link rel="icon" type="image/png" sizes="192x192" href="/footing-pro/images/favicon-192.png">'
                 + '<link rel="apple-touch-icon" sizes="180x180" href="/footing-pro/images/apple-touch-icon.png">';
  } else {
    return res.status(404).send('Not found');
  }

  // .enc files live in /private — bundled into the function via vercel.json
  // "includeFiles": "private/*.enc"
  // They are NOT in /public (which is CDN-only and not fs-accessible from functions).
  const encPath = path.join(process.cwd(), 'private', encFile);
  let encData;
  try { encData = fs.readFileSync(encPath, 'utf-8').trim(); }
  catch(e) {
    // Do NOT expose file paths, directory listings, or internal error details
    return res.status(500).send(errPage('Server Error', 'Content temporarily unavailable. Please try again later.'));
  }

  const dot = encData.indexOf('.');
  if (dot === -1) return res.status(500).send(errPage('Server Error', 'Content temporarily unavailable. Please try again later.'));

  let html;
  try {
    const nonce      = Buffer.from(encData.slice(0, dot), 'base64');
    const ciphertext = Buffer.from(encData.slice(dot + 1), 'base64');
    const authTag    = ciphertext.slice(ciphertext.length - 16);
    const encrypted  = ciphertext.slice(0, ciphertext.length - 16);
    const decipher   = createDecipheriv('aes-256-gcm', keyBuf, nonce);
    decipher.setAuthTag(authTag);
    html = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf-8');
  } catch(e) {
    // Do NOT expose decryption error details
    return res.status(500).send(errPage('Server Error', 'Content temporarily unavailable. Please try again later.'));
  }

  html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);

  // ── Browser path ─────────────────────────────────────
  // Two 100% reliable protections — no blur (too unreliable):
  // 1. Ctrl+S → intercept → download copyright notice
  // 2. Print  → handled by each page's own overlay (not duplicated here)
  // 3. view-source → obfuscated with a random per-request key + base64

  const copyrightHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Protected</title></head>`
    + `<body style="margin:0;background:#0A1A2E;display:flex;align-items:center;`
    + `justify-content:center;min-height:100vh;font-family:sans-serif">`
    + `<div style="text-align:center;padding:40px">`
    + `<div style="font-size:3rem;margin-bottom:20px">&#x1F512;</div>`
    + `<h2 style="color:#C17B1A;margin-bottom:12px">&#169; Civil Engineering Suite</h2>`
    + `<p style="color:#8AA3C7;line-height:1.8">Eng. Aymn Asi &#8212; All Rights Reserved<br>`
    + `Unauthorized copying or reproduction is strictly prohibited.</p>`
    + `</div></body></html>`;

  const protectionScript = `<script>(function(){`

    // ── 1. Ctrl+S / Cmd+S ──────────────────────────────
    + `document.addEventListener('keydown',function(e){`
    + `if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){`
    + `e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();`
    + `var _b=new Blob(['${copyrightHtml.replace(/'/g,"\\'").replace(/\n/g,'')}'],{type:'text/html'});`
    + `var _a=document.createElement('a');`
    + `_a.href=URL.createObjectURL(_b);_a.download='${pageFilename}';`
    + `document.body.appendChild(_a);_a.click();`
    + `setTimeout(function(){document.body.removeChild(_a);URL.revokeObjectURL(_a.href);},100);`
    + `}},true);`

    // ── 2. Print: handled by each page's own overlay — NOT duplicated here
    //    Reason: duplicating beforeprint/afterprint with innerHTML wipe causes
    //    body to go blank when navigating between pages via document.write bootstrap.

    + `})();\u003c/script>`;

  // Inject before </body>
  html = html.replace(/<\/body>/i, protectionScript + '</body>');

  // Minify to single line
  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g, '><')
    .replace(/\s{2,}/g, ' ')
    .replace(/\n|\r/g, '')
    .trim();

  // ── Per-request random XOR key ────────────────────────
  // A fresh random byte is generated on every request so there is no
  // static constant that can be read from source or cached responses.
  // This is obfuscation only (not encryption — the AES-256-GCM layer is
  // the real protection). It raises the bar from "trivial view-source" to
  // "requires active per-request interception."
  const _r = randomBytes(1)[0];
  const xored   = Buffer.from(html, 'utf-8').map(b => b ^ _r);
  const payload = xored.toString('base64');

  const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle  = titleMatch ? titleMatch[1] : 'Civil Engineering Suite';

  // The decode key (_r) is embedded as a numeric literal — it has a different
  // value on every response, so it cannot be hardcoded by a scraper.
  const bootstrap = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0"><meta name="robots" content="noindex"><title>${pageTitle}</title>${faviconLinks}</head><body><script>(function(){try{var d="${payload}";var b=atob(d);var u=new Uint8Array(b.length);var k=${_r};for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i)^k;var h=new TextDecoder("utf-8").decode(u);document.open();document.write(h);document.close();}catch(e){document.body.innerHTML="<p style='padding:40px;color:#C17B1A;font-family:sans-serif'>Error loading content. Please refresh.</p>";}})();<\/script></body></html>`;

  res.setHeader('Content-Type',          'text/html; charset=utf-8');
  res.setHeader('Cache-Control',         'no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.status(200).send(bootstrap);
};

function errPage(t, m) {
  return `<!DOCTYPE html><html><head><title>${t}</title></head>`
    + `<body style="font-family:sans-serif;padding:40px"><h2>${t}</h2><p>${m}</p></body></html>`;
}
// listDir() removed — exposing directory contents in error responses
// is an information disclosure vulnerability (CWE-548).
