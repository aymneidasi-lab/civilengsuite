export const config = { runtime: 'edge' };

export default async function handler(req) {

  const keyHex = (process.env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64) {
    return err('CES_DECRYPT_KEY not set in Vercel Environment Variables.');
  }

  const pathname = new URL(req.url).pathname.replace(/\/+$/, '') || '/';
  let encFile;
  if (pathname === '' || pathname === '/' || pathname === '/index.html') {
    encFile = 'pc_suite.enc';
  } else if (pathname === '/footing-pro' || pathname === '/footing-pro/index.html') {
    encFile = 'footing_pro.enc';
  } else {
    return new Response('Not found', { status: 404 });
  }

  // Fetch the .enc file from the same deployment's static files
  const origin = new URL(req.url).origin;
  let encData;
  try {
    const res = await fetch(`${origin}/public/${encFile}`);
    if (!res.ok) throw new Error(`status ${res.status}`);
    encData = await res.text();
  } catch (e) {
    return err(`Cannot load ${encFile}: ${e.message}`);
  }

  const dot = encData.indexOf('.');
  if (dot === -1) return err('Bad encrypted file format');

  let key;
  try {
    key = await crypto.subtle.importKey(
      'raw', hex(keyHex), { name: 'AES-GCM' }, false, ['decrypt']
    );
  } catch(e) { return err(`Key error: ${e.message}`); }

  let html;
  try {
    const buf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64(encData.slice(0, dot)) },
      key,
      b64(encData.slice(dot + 1))
    );
    html = new TextDecoder().decode(buf);
  } catch(e) { return err(`Decrypt failed: ${e.message}`); }

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8',
               'Cache-Control': 'public, max-age=3600' }
  });
}

const err = m => new Response(
  `<!DOCTYPE html><html><body><h2>Error</h2><p>${m}</p></body></html>`,
  { status: 500, headers: { 'Content-Type': 'text/html' } }
);

const hex = h => { const b=new Uint8Array(h.length/2); for(let i=0;i<h.length;i+=2)b[i/2]=parseInt(h.slice(i,i+2),16); return b; };
const b64 = s => { const bin=atob(s),b=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++)b[i]=bin.charCodeAt(i); return b; };
