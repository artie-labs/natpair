// natpair probe receiver for an AWS Lambda function URL.
//
// It speaks the same protocol as probetest.Handler in the Go tests: a NAT posts
// random bytes with a nonce, and the reply confirms the nonce, the byte count,
// the SHA-256 of the body and the source IP the receiver saw, and sends the body
// back so the reply spans full-size packets too. The function URL requires IAM
// authentication, so the handler does not authenticate callers itself.
import { createHash } from 'node:crypto';

const NONCE_HEADER = 'x-nat-probe-nonce';
const MAX_BYTES = 65536;

export const handler = async (event) => {
  const http = event.requestContext.http;
  const headers = Object.fromEntries(Object.entries(event.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]));
  const nonce = headers[NONCE_HEADER] ?? '';
  if (http.method !== 'POST' || !nonce || nonce.length > 64) {
    return error(400, 'expected a probe upload');
  }

  const upload = Buffer.from(event.body ?? '', event.isBase64Encoded ? 'base64' : 'utf8');
  if (upload.length > MAX_BYTES) {
    return error(400, 'invalid probe upload');
  }

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      nonce,
      bytes: upload.length,
      sha256: createHash('sha256').update(upload).digest('hex'),
      source_ip: http.sourceIp,
      echo: upload.toString('base64'),
    }),
  };
};

function error(statusCode, message) {
  return { statusCode, headers: { 'Content-Type': 'text/plain' }, body: message };
}
