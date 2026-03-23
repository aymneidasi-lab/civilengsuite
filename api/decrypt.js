/**
 * Civil Engineering Suite — AES-256-GCM Decrypt
 */

const fs   = require('fs');
const path = require('path');
const { createDecipheriv } = require('crypto');

const BOT_RE = /googlebot|google-inspectiontool|googleother|bingbot|yandexbot|duckduckbot|baiduspider|applebot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|slackbot|discordbot/i;
const KEY    = 0x5A;

module.exports = async function handler(req, res) {

  const keyHex = (process.env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64)
    return res.status(500).send(errPage('Config Error', 'CES_DECRYPT_KEY missing'));

  let keyBuf;
  try { keyBuf = Buffer.from(keyHex, 'hex'); }
  catch(e) { return res.status(500).send(errPage('Key Error', e.message)); }

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

  // ── Bot path ─────────────────────────────────────────
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

  // ── Browser path ─────────────────────────────────────

  const copyrightInner = `<head><meta charset="UTF-8"><title>Protected<\\/title><\\/head>`
    + `<body style="margin:0;background:#0A1A2E;display:flex;align-items:center;`
    + `justify-content:center;min-height:100vh;font-family:sans-serif">`
    + `<div style="text-align:center;padding:40px">`
    + `<div style="font-size:3rem;margin-bottom:20px">\\uD83D\\uDD12<\\/div>`
    + `<h2 style="color:#C17B1A;margin-bottom:12px">\\u00A9 Civil Engineering Suite<\\/h2>`
    + `<p style="color:#8AA3C7">Eng. Aymn Asi \\u2014 All Rights Reserved<br>`
    + `Unauthorized copying is strictly prohibited.<\\/p><\\/div><\\/body>`;

  // CASES that cause blur — and how we handle each:
  // 1. Tab switch    → visibilitychange(hidden) fires → cancel timer ✅
  // 2. Minimize      → visibilitychange(hidden) fires → cancel timer ✅
  // 3. Link click    → mousedown on <a> sets _navigating=true → cancel timer ✅
  // 4. beforeunload  → page is leaving → cancel timer ✅
  // 5. File menu     → none of the above → 300ms passes → swap DOM ✅
  const protectionScript = `<script>(function(){`
    + `var _r=null,_ready=false,_timer=null,_swapped=false,_navigating=false;`

    + `window.addEventListener('load',function(){`
    + `_r=document.documentElement.outerHTML;`
    + `_ready=true;`
    + `},false);`

    // Detect link/button clicks → user is navigating, not opening File menu
    + `document.addEventListener('mousedown',function(e){`
    + `var t=e.target;`
    + `while(t&&t!==document){`
    + `if(t.tagName==='A'||t.tagName==='BUTTON'||t.type==='submit'){`
    + `_navigating=true;`
    + `setTimeout(function(){_navigating=false;},2000);`
    + `break;`
    + `}`
    + `t=t.parentNode;`
    + `}`
    + `},true);`

    // beforeunload = page is navigating away → cancel swap
    + `window.addEventListener('beforeunload',function(){`
    + `_navigating=true;`
    + `clearTimeout(_timer);`
    + `},false);`

    // visibilitychange hidden = tab switch or minimize → cancel swap
    + `document.addEventListener('visibilitychange',function(){`
    + `if(document.hidden){clearTimeout(_timer);}`
    + `},false);`

    // blur → wait 300ms, then check all conditions
    + `window.addEventListener('blur',function(){`
    + `if(!_ready)return;`
    + `clearTimeout(_timer);`
    + `_timer=setTimeout(function(){`
    + `if(document.hidden)return;`  // tab/minimize
    + `if(_navigating)return;`      // link click / navigation
    // File menu: swap DOM
    + `_swapped=true;`
    + `document.documentElement.innerHTML='${copyrightInner}';`
    + `},300);`
    + `},false);`

    // focus → restore
    + `window.addEventListener('focus',function(){`
    + `clearTimeout(_timer);`
    + `_navigating=false;`
    + `if(!_ready||!_r)return;`
    + `if(_swapped){`
    + `_swapped=false;`
    + `document.open();document.write(_r);document.close();`
    + `}`
    + `},false);`

    // Ctrl+S
    + `document.addEventListener('keydown',function(e){`
    + `if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){`
    + `e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();`
    + `var _h='<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Protected</title></head>'`
    + `+'<body style="margin:0;background:#0A1A2E;display:flex;align-items:center;'`
    + `+'justify-content:center;min-height:100vh;font-family:sans-serif">'`
    + `+'<div style="text-align:center;padding:40px">'`
    + `+'<div style="font-size:3rem">\\uD83D\\uDD12</div>'`
    + `+'<h2 style="color:#C17B1A">\\u00A9 Civil Engineering Suite \\u2014 Eng. Aymn Asi</h2>'`
    + `+'<p style="color:#8AA3C7">All Rights Reserved</p></div></body></html>';`
    + `var _b=new Blob([_h],{type:'text/html'});`
    + `var _a=document.createElement('a');`
    + `_a.href=URL.createObjectURL(_b);_a.download='${pageFilename}';`
    + `document.body.appendChild(_a);_a.click();`
    + `setTimeout(function(){document.body.removeChild(_a);URL.revokeObjectURL(_a.href);},100);`
    + `}},true);`

    // Print
    + `window.addEventListener('beforeprint',function(){`
    + `if(!_ready)return;`
    + `document.documentElement.innerHTML='${copyrightInner}';`
    + `});`
    + `window.addEventListener('afterprint',function(){`
    + `if(!_ready||!_r)return;`
    + `document.open();document.write(_r);document.close();`
    + `});`

    + `})();\u003c/script>`;

  html = html.replace(/<\/body>/i, protectionScript + '</body>');

  // Minify
  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g, '><')
    .replace(/\s{2,}/g, ' ')
    .replace(/\n|\r/g, '')
    .trim();

  const xored   = Buffer.from(html, 'utf-8').map(b => b ^ KEY);
  const payload = xored.toString('base64');

  const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle  = titleMatch ? titleMatch[1] : 'Civil Engineering Suite';

  const bootstrap = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0"><meta name="robots" content="noindex"><title>${pageTitle}</title>${faviconLinks}</head><body><script>(function(){try{var p="${payload}";var b=atob(p);var u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i)^0x5A;var h=new TextDecoder("utf-8").decode(u);document.open();document.write(h);document.close();}catch(e){document.body.innerHTML="<p style='padding:40px;color:#C17B1A;font-family:sans-serif'>Error: "+e.message+"</p>";}})();<\/script></body></html>`;

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
