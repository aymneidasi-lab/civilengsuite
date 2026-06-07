export async function onRequest(context) {
  const { env } = context;
  let kvStatus = 'KV not bound';
  try {
    if (env.CES_SESSIONS) {
      await env.CES_SESSIONS.put('test-key', 'hello');
      const val = await env.CES_SESSIONS.get('test-key');
      kvStatus = `KV works: value = ${val}`;
    } else {
      kvStatus = 'KV binding is missing from env';
    }
  } catch (e) {
    kvStatus = `KV error: ${e.message}`;
  }
  const key = env.CES_DECRYPT_KEY ? env.CES_DECRYPT_KEY.slice(0,10)+'…' : 'missing';
  return new Response(
    `<html><body style="background:#0A1A2E;color:#C17B1A;font-family:sans-serif;padding:40px">
      <h1>Diagnostic</h1>
      <p>CES_DECRYPT_KEY: ${key}</p>
      <p>${kvStatus}</p>
      <p>If you see this, your bindings and environment are correct.</p>
      <p>Now replace this file with the corrected v14.</p>
    </body></html>`,
    { headers: { 'Content-Type': 'text/html' } }
  );
}