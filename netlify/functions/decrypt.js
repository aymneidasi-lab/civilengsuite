/**
 * netlify/functions/decrypt.js
 * Thin wrapper — calls your existing api/decrypt.js with zero changes.
 */
'use strict';

const vercelHandler = require('../../api/decrypt');

exports.handler = async function netlifyDecrypt(event) {
  const outHeaders = {};
  let response = { statusCode: 500, headers: {}, body: 'Internal Server Error' };

  const req = {
    url: event.path + (event.rawQuery ? '?' + event.rawQuery : ''),
    headers: {
      ...event.headers,
      'x-real-ip': event.headers['x-nf-client-connection-ip'] || event.headers['x-real-ip'] || '',
    },
    socket: { remoteAddress: event.headers['x-nf-client-connection-ip'] || '' },
  };

  const res = {
    setHeader(key, value) { outHeaders[key] = String(value); },
    status(code) {
      const chain = {
        send(body) {
          response = { statusCode: code, headers: { ...outHeaders }, body: String(body) };
          return chain;
        },
        set(key, value) {
          outHeaders[key] = String(value);
          return chain;
        },
        end() {
          response = { statusCode: code, headers: { ...outHeaders }, body: '' };
          return chain;
        },
      };
      return chain;
    },
  };

  await vercelHandler(req, res);
  return response;
};
