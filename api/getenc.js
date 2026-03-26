/**
 * /api/getenc — DISABLED
 *
 * This endpoint previously served raw .enc files to the browser.
 * It has been disabled because:
 *
 *   1. decrypt.js already reads .enc files server-side via fs.readFileSync —
 *      there is no legitimate use case for a browser to fetch the raw
 *      encrypted payload directly.
 *
 *   2. Exposing the encrypted files over HTTP adds unnecessary attack surface.
 *      Even though AES-256-GCM is strong, there is no reason to hand
 *      attackers the ciphertext to work with offline.
 *
 *   3. No authentication or rate-limiting was in place on this route.
 *
 * If you ever need to restore server-to-server .enc file transfer,
 * add proper authentication (shared secret header or signed URL) first.
 */

export default function handler(req, res) {
  res.status(404).send('Not found');
}
