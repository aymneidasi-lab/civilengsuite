/**
 * Civil Engineering Suite — AES-256-GCM Decrypt
 */

const fs   = require('fs');
const path = require('path');
const { createDecipheriv } = require('crypto');

const BOT_RE = /googlebot|google-inspectiontool|googleother|bingbot|yandexbot|duckduckbot|baiduspider|applebot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|slackbot|discordbot/i;

module.exports = async function handler(req, res) {

  const keyHex = (process.env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64)
    return res.status(500).send(errPage('Config Error', 'CES_DECRYPT_KEY missing'));

  let keyBuf;
  try { keyBuf = Buffer.from(keyHex, 'hex'); }
  catch(e) { return res.status(500).send(errPage('Key Error', e.message)); }

  const pathname = (req.url||'/').split('?')[0].replace(/\/+$/,'') || '/';

  let encFile, baseHref, faviconLinks;
  if (pathname === '' || pathname === '/' || pathname === '/index.html') {
    encFile      = 'pc_suite.enc';
    baseHref     = '/';
    faviconLinks = '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                 + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">';
  } else if (pathname.startsWith('/footing-pro')) {
    encFile      = 'footing_pro.enc';
    baseHref     = '/footing-pro/';
    faviconLinks = '<link rel="icon" type="image/png" sizes="32x32" href="/footing-pro/images/favicon-32.png">'
                 + '<link rel="icon" type="image/png" sizes="192x192" href="/footing-pro/images/favicon-192.png">'
                 + '<link rel="apple-touch-icon" sizes="180x180" href="/footing-pro/images/apple-touch-icon.png">';
  } else {
    return res.status(404).send('Not found');
  }

  const encPath = path.join(process.cwd(), 'public', encFile);
  let encData;
  try { encData = fs.readFileSync(encPath, 'utf-8').trim(); }
  catch(e) {
    return res.status(500).send(errPage('File Error',
      `Cannot read ${encFile}: ${e.message} | public/: ${listDir(path.join(process.cwd(),'public'))}`));
  }

  const dot = encData.indexOf('.');
  if (dot === -1) return res.status(500).send(errPage('Format Error', 'Bad .enc format'));

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
    return res.status(500).send(errPage('Decrypt Error', e.message));
  }

  html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);

  // ── Bot path: plain HTML for search engines ──────────
  const ua    = req.headers['user-agent'] || '';
  const isBot = BOT_RE.test(ua);

  if (isBot) {
    const botHtml = html.replace(
      /<meta\s+name="robots"\s+content="noindex[^"]*"/gi,
      '<meta name="robots" content="index, follow"'
    );
    res.setHeader('Content-Type',  'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
    res.setHeader('X-Robots-Tag',  'index, follow');
    return res.status(200).send(botHtml);
  }

  // ── Browser path: obfuscated bootstrap ───────────────
  // XOR + base64 the full HTML
  const KEY     = 0x5A;
  const xored   = Buffer.from(html, 'utf-8').map(b => b ^ KEY);
  const payload = xored.toString('base64');

  // Encode the favicon links too so they don't appear in view-source or saved MHTML
  const favXored   = Buffer.from(faviconLinks, 'utf-8').map(b => b ^ KEY);
  const favPayload = favXored.toString('base64');

  // Extract real title server-side — shows correctly in tab immediately
  const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle  = titleMatch ? titleMatch[1] : 'Civil Engineering Suite';

  const bootstrap = `<!DOCTYPE html><html><head><meta charset="UTF-8">`
  + `<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0">`
  + `<meta name="robots" content="noindex">`
  + `<title>${pageTitle}</title>`
  + `</head><body><script>`
  + `(function(){`
  + `try{`
  // Inject favicons dynamically so they don't appear in saved HTML source
  + `var f=new TextDecoder("utf-8").decode(new Uint8Array(atob("${favPayload}").split("").map(function(c){return c.charCodeAt(0)^0x5A;})));`
  + `var t=document.createElement("template");t.innerHTML=f;`
  + `document.head.appendChild(t.content);`
  // Decode and write the full page
  + `var p="${payload}";`
  + `var b=atob(p);`
  + `var u=new Uint8Array(b.length);`
  + `for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i)^0x5A;`
  + `var h=new TextDecoder("utf-8").decode(u);`
  + `document.open();`
  + `document.write(h);`
  + `document.close();`
  + `}catch(e){`
  + `document.body.innerHTML="<p style='font-family:sans-serif;padding:40px;color:#C17B1A'>Error: "+e.message+"</p>";`
  + `}`
  + `})();`
  + `<\/script></body></html>`;

  res.setHeader('Content-Type',          'text/html; charset=utf-8');
  res.setHeader('Cache-Control',         'no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.status(200).send(bootstrap);
};

function errPage(t, m) {
  return `<!DOCTYPE html><html><head><title>${t}</title></head>`
    + `<body style="font-family:sans-serif;padding:40px"><h2>${t}</h2><p>${m}</p></body></html>`;
}
function listDir(dir) {
  try { return fs.readdirSync(dir).join(', '); } catch(e) { return e.message; }
}
