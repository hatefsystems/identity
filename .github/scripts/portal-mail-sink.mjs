import assert from 'node:assert/strict';
import { timingSafeEqual } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';

const limit = 32 * 1024;
const canonicalToken = (token) => /^[A-Za-z0-9_-]{43}$/.test(token) &&
  Buffer.from(token, 'base64url').toString('base64url') === token;

export function deletionMail(message, { origin, recipient, from }) {
  assert(Buffer.byteLength(message) <= limit, 'Unbounded fixture mail');
  const split = message.indexOf('\r\n\r\n');
  assert(split > 0, 'Missing fixture mail headers');
  const headers = message.slice(0, split);
  assert(headers.includes(`From: <${from}>\r\n`), 'Unexpected fixture sender');
  assert(headers.includes(`To: <${recipient}>\r\n`), 'Unexpected fixture recipient');
  assert(!/^(?:Cc|Bcc):/im.test(headers), 'Fixture mail disclosed another recipient');
  const messageID = headers.match(/^Message-ID: (<deletion\.[a-f0-9-]{36}@[^<>\s]+>)$/m)?.[1];
  assert(messageID, 'Missing stable deletion message identity');
  const boundary = headers.match(/boundary="([a-zA-Z0-9-]+)"/)?.[1];
  assert(boundary, 'Expected multipart alternative mail');
  const parts = message.slice(split + 4).split(`--${boundary}`)
    .filter((part) => part.startsWith('\r\nContent-'));
  assert.equal(parts.length, 2, 'Expected text and HTML alternatives');
  const bodies = parts.map((part) => {
    assert(part.includes('Content-Transfer-Encoding: quoted-printable\r\n'), 'Unexpected mail encoding');
    return part.slice(part.indexOf('\r\n\r\n') + 4)
      .replace(/=\r\n/g, '')
      .replace(/=([0-9A-F]{2})/gi, (_, byte) => String.fromCharCode(parseInt(byte, 16)));
  });
  assert(parts.some((part) => /Content-Type: text\/plain;/.test(part)) &&
    parts.some((part) => /Content-Type: text\/html;/.test(part)), 'Missing alternative media types');
  const links = bodies.flatMap((body) => body.match(/https:\/\/[^\s<>"']+/g) || []);
  assert.equal(links.length, 2, 'Mail must contain only its recovery link in each alternative');
  assert(links[0] === links[1], 'Mail alternatives disagree about recovery');
  const link = new URL(links[0]);
  const token = link.hash.slice(7);
  assert(link.origin === origin && link.pathname === '/recover-account' && !link.search &&
    link.hash.startsWith('#token=') && canonicalToken(token), 'Invalid canonical recovery link');
  assert(!/<(?:img|script|iframe)\b/i.test(bodies.join('')), 'Mail included a remote asset');
  const expires = bodies[0].match(/until (\d{4}-\d{2}-\d{2}T[0-9:.]+Z) \(UTC\)/)?.[1];
  assert(expires && Number.isFinite(Date.parse(expires)), 'Mail omitted its original deadline');
  return { recipient, message_id: messageID, token, link: link.href, expires_at: expires };
}

// Implicit TLS only: no plaintext listener, external relay, transcript, or spool.
// Fault injection is recipient-scoped, and cannot deliver outside this run.
export async function startMailSink({ key, cert, username, password, from, runID, origin, onSecrets = () => {} }) {
  assert(/^[a-f0-9]{32}$/.test(runID), 'Mail sink requires a fixture run');
  const publicOrigin = new URL(origin);
  assert(publicOrigin.hostname === 'localhost' && publicOrigin.protocol === 'https:' &&
    publicOrigin.port && publicOrigin.origin === origin,
    'Mail sink requires a local HTTPS portal');
  assert(username && password && from.endsWith(`@${runID}.example.test`), 'Mail sink requires owned credentials');
  const connections = new Set();
  const messages = [];
  const faults = new Map();
  const evidence = { tls: 0, authenticated: 0, authRejected: 0, recipientRejected: 0, temporary: 0, accepted: 0 };
  const owned = (recipient) => /^[a-zA-Z0-9.+_-]+@[a-f0-9]{32}\.example\.test$/.test(recipient) &&
    recipient.endsWith(`@${runID}.example.test`);
  const expected = Buffer.from(`\0${username}\0${password}`);
  const server = createServer({ key, cert, minVersion: 'TLSv1.2', handshakeTimeout: 5000 }, (socket) => {
    evidence.tls++;
    let buffer = '';
    let authenticated = false;
    let sender = false;
    let recipient = '';
    let data = null;
    let bytes = 0;
    const reply = (line) => socket.write(`${line}\r\n`);
    socket.setEncoding('utf8');
    socket.setTimeout(5000, () => socket.destroy());
    reply('220 localhost fixture relay');
    socket.on('data', (chunk) => {
      buffer += chunk;
      if (Buffer.byteLength(buffer) > limit || (data !== null && bytes + Buffer.byteLength(buffer) > limit)) {
        socket.destroy();
        return;
      }
      while (buffer.includes('\r\n')) {
        const index = buffer.indexOf('\r\n');
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        if (data !== null) {
          if (line !== '.') {
            const unstuffed = line.startsWith('..') ? line.slice(1) : line;
            bytes += Buffer.byteLength(unstuffed) + 2;
            data.push(unstuffed);
            if (bytes > limit) socket.destroy();
            continue;
          }
          try {
            assert(messages.length < 64, 'Fixture mail capture limit');
            const notice = deletionMail(data.join('\r\n') + '\r\n', { origin, recipient, from });
            onSecrets([notice.recipient, notice.token, notice.link]);
            const remaining = faults.get(recipient) || 0;
            const accepted = remaining === 0;
            messages.push({ ...notice, accepted });
            if (accepted) {
              evidence.accepted++;
              reply('250 accepted');
            } else {
              faults.set(recipient, remaining - 1);
              evidence.temporary++;
              reply('451 fixture temporary failure');
            }
          } catch {
            // Mail parsing errors are deliberately not retained or printed.
            reply('554 invalid fixture message');
          }
          data = null;
          bytes = 0;
          sender = false;
          recipient = '';
        } else if (/^EHLO [^\r\n]+$/.test(line)) {
          reply('250-localhost\r\n250 AUTH PLAIN');
        } else if (line.startsWith('AUTH PLAIN ')) {
          const presented = Buffer.from(line.slice(11), 'base64');
          authenticated = presented.length === expected.length && timingSafeEqual(presented, expected);
          presented.fill(0);
          if (authenticated) evidence.authenticated++;
          else evidence.authRejected++;
          reply(authenticated ? '235 authenticated' : '535 authentication failed');
        } else if (line === 'QUIT') {
          socket.end('221 closing\r\n');
        } else if (!authenticated) {
          reply('530 authentication required');
        } else if (line === `MAIL FROM:<${from}>`) {
          sender = true;
          recipient = '';
          reply('250 sender accepted');
        } else if (line.startsWith('RCPT TO:')) {
          const address = line.match(/^RCPT TO:<([^<>]+)>$/)?.[1];
          if (!sender || recipient || !address || !owned(address)) {
            evidence.recipientRejected++;
            reply('550 run-owned single recipient required');
          } else {
            recipient = address;
            reply('250 recipient accepted');
          }
        } else if (line === 'DATA' && sender && recipient) {
          data = [];
          bytes = 0;
          reply('354 send data');
        } else {
          reply('503 unsupported fixture command');
        }
      }
    });
    socket.on('error', () => {});
  });
  server.on('connection', (socket) => {
    connections.add(socket);
    socket.on('close', () => connections.delete(socket));
    socket.on('error', () => {});
  });
  server.on('tlsClientError', () => {});
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    port: server.address().port,
    messages,
    evidence,
    rejectNext(recipient) {
      assert(owned(recipient), 'Cannot inject a fault for a foreign recipient');
      faults.set(recipient, (faults.get(recipient) || 0) + 1);
    },
    async waitFor(recipient, count = 1) {
      assert(owned(recipient) && count >= 1 && count <= 16, 'Invalid fixture mail wait');
      const end = Date.now() + 15_000;
      while (Date.now() < end) {
        const accepted = messages.filter((message) => message.recipient === recipient && message.accepted);
        if (accepted.length >= count) return accepted[count - 1];
        await delay(50);
      }
      throw new Error('Timed out waiting for authenticated fixture mail');
    },
    async close() {
      expected.fill(0);
      messages.length = 0;
      faults.clear();
      await new Promise((resolve) => {
        server.close(resolve);
        for (const socket of connections) socket.destroy();
      });
    },
  };
}
