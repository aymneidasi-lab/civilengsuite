/**
 * Civil Engineering Suite — AES-256-GCM Decrypt Edge Function
 * Environment variable required: CES_DECRYPT_KEY (64 hex chars)
 */

export const config = { runtime: 'edge' };

export default async function handler(req) {

  /* ── 1. Key ── */
  const keyHex = (process.env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64) {
    return html500('CES_DECRYPT_KEY not set or invalid. Add it in Vercel → Settings → Environment Variables.');
  }

  /* ── 2. Which page ── */
  const pathname = new URL(req.url).pathname.replace(/\/+$/, '') || '/';
  let encFile;
  if (pathname === '' || pathname === '/' || pathname === '/index.html') {
    encFile = 'pc_suite.enc';
  } else if (pathname === '/footing-pro' || pathname === '/footing-pro/index.html') {
    encFile = 'footing_pro.enc';
  } else {
    return new Response('Not found', { status: 404 });
  }

  /* ── 3. Load .enc via internal API route ── */
  const origin = new URL(req.url).origin;
  const encUrl = `${origin}/api/getenc?file=${encFile}`;

  let encData;
  try {
    const res = await fetch(encUrl);
    if (!res.ok) throw new Error(`getenc returned ${res.status}`);
    encData = await res.text();
  } catch (err) {
    return html500(`Cannot load encrypted file: ${err.message}`);
  }

  /* ── 4. Parse ── */
  const dot = encData.indexOf('.');
  if (dot === -1) return html500('Encrypted file format invalid');
  const nonce      = b64ToBytes(encData.slice(0, dot));
  const ciphertext = b64ToBytes(encData.slice(dot + 1));

  /* ── 5. Import key ── */
  let cryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      'raw', hexToBytes(keyHex), { name: 'AES-GCM' }, false, ['decrypt']
    );
  } catch (err) {
    return html500(`Key error: ${err.message}`);
  }

  /* ── 6. Decrypt ── */
  let plaintext;
  try {
    const buf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce }, cryptoKey, ciphertext
    );
    plaintext = new TextDecoder().decode(buf);
  } catch (err) {
    return html500(`Decryption failed: ${err.message}`);
  }

  /* ── 7. Serve ── */
  return new Response(plaintext, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, must-revalidate',
    },
  });
}

function html500(msg) {
  return new Response(`<!DOCTYPE html><html><body><h2>Server Error</h2><p>${msg}</p></body></html>`, {
    status: 500,
    headers: { 'Content-Type': 'text/html' }
  });
}

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i/2] = parseInt(hex.slice(i, i+2), 16);
  return b;
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}
