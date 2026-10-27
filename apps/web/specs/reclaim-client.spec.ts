/** @jest-environment node */

import {
  isReclaimToken,
  ReclaimClient,
  type ReclaimProof,
} from '../app/_lib/portal/reclaim-client';

const origin = 'https://identity.example.test';
const token = Buffer.alloc(32, 123).toString('base64url');
const json = (value: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
const signal = () => new AbortController().signal;

describe('anonymous reclaim transport', () => {
  it('uses only the exact anonymous endpoints, omitting all cookies and portal authority without a browser key', async () => {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(json({ factor: 'totp', ignored: 'private metadata' }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const client = new ReclaimClient({ origin, fetcher });
    expect(await client.options(token, signal())).toEqual({ factor: 'totp' });
    const sent = jest.fn();
    await client.complete({ token, factor: 'totp', code: '012345' }, signal(), sent);
    expect(sent).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      `${origin}/api/v1/auth/deletion/reclaim/options`,
      `${origin}/api/v1/auth/deletion/reclaim/`,
    ]);
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({ token });
    expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({
      token,
      factor: 'totp',
      code: '012345',
    });
    for (const [url, request] of fetcher.mock.calls) {
      expect(request).toMatchObject({
        method: 'POST',
        credentials: 'omit',
        mode: 'cors',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
      });
      const headers = new Headers(request.headers);
      expect([...headers.keys()].sort()).toEqual(['accept', 'content-type']);
      expect(headers.get('Content-Type')).toBe('application/json');
      expect(url).not.toContain(token);
    }
  });

  it('preserves the server-selected WebAuthn assertion contract and confirms only a 204', async () => {
    const options = { factor: 'webauthn', webauthn: { publicKey: { challenge: 'AA' } } };
    const assertion = { id: 'credential-id', response: { signature: 'AA' } };
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(json(options))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const client = new ReclaimClient({ origin, fetcher });
    expect(await client.options(token, signal())).toEqual(options);
    await client.complete({ token, factor: 'webauthn', assertion }, signal());
    expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({
      token,
      factor: 'webauthn',
      assertion,
    });
    const wrongSuccess = jest.fn().mockResolvedValue(json({}, 200));
    await expect(
      new ReclaimClient({ origin, fetcher: wrongSuccess }).complete(
        { token, factor: 'totp', code: '012345' },
        signal()
      )
    ).rejects.toMatchObject({ code: 'invalid_response', uncertain: true });
    expect(wrongSuccess).toHaveBeenCalledTimes(1);
  });

  it('validates exactly 32 canonical bytes and six text digits before any transmission', async () => {
    const fetcher = jest.fn();
    const client = new ReclaimClient({ origin, fetcher });
    expect(isReclaimToken(token)).toBe(true);
    for (const invalid of [
      '',
      token.slice(1),
      `${token}A`,
      `${token}=`,
      `${token}\n`,
      `${'A'.repeat(42)}B`,
      `${'A'.repeat(42)}-`,
      `${'A'.repeat(42)}_`,
      'A'.repeat(42) + '+',
      null,
      123,
    ]) {
      expect(isReclaimToken(invalid)).toBe(false);
      await expect(client.options(invalid as string, signal())).rejects.toMatchObject({
        code: 'invalid_request',
      });
    }
    for (const code of [
      '',
      '12345',
      '1234567',
      '123456\n',
      '12 456',
      'abcdef',
      '\uff11\uff12\uff13\uff14\uff15\uff16',
    ])
      await expect(
        client.complete({ token, factor: 'totp', code }, signal())
      ).rejects.toMatchObject({ code: 'invalid_request' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    {},
    { factor: ['webauthn', 'totp'] },
    { factor: 'sms' },
    { factor: 'webauthn' },
    { factor: 'webauthn', webauthn: [] },
  ])('rejects malformed factor options without a fallback or retry: %j', async (value) => {
    const fetcher = jest.fn().mockResolvedValue(json(value));
    await expect(
      new ReclaimClient({ origin, fetcher }).options(token, signal())
    ).rejects.toMatchObject({ code: 'invalid_response', uncertain: false });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('does not follow redirects or accept a response from another URL', async () => {
    for (const property of ['redirected', 'url']) {
      const response = new Response(null, { status: 204 });
      Object.defineProperty(response, property, {
        value:
          property === 'redirected' ? true : 'https://elsewhere.test/api/v1/auth/deletion/reclaim/',
      });
      const fetcher = jest.fn().mockResolvedValue(response);
      await expect(
        new ReclaimClient({ origin, fetcher }).complete(
          { token, factor: 'totp', code: '012345' },
          signal()
        )
      ).rejects.toMatchObject({ code: 'invalid_response', uncertain: true });
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
    for (const invalid of [
      origin + '/',
      origin + '?token=x',
      origin + '#token=x',
      'ftp://example.test',
    ])
      expect(() => new ReclaimClient({ origin: invalid })).toThrow('invalid_origin');
  });

  it('bounds streaming and declared response sizes and cancels an oversized stream', async () => {
    const cancel = jest.fn();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(256 * 1024 + 1));
      },
      cancel,
    });
    const fetcher = jest.fn().mockResolvedValue(
      new Response(stream, {
        headers: { 'Content-Type': 'application/json' },
      })
    );
    await expect(
      new ReclaimClient({ origin, fetcher }).options(token, signal())
    ).rejects.toMatchObject({ code: 'invalid_response' });
    expect(cancel).toHaveBeenCalledTimes(1);
    const large = jest.fn().mockResolvedValue(json({}, 200, { 'Content-Length': '9999999' }));
    await expect(
      new ReclaimClient({ origin, fetcher: large }).options(token, signal())
    ).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('bounds outgoing assertion bodies without sending or retaining the rejected payload in errors', async () => {
    const fetcher = jest.fn();
    const sent = jest.fn();
    await expect(
      new ReclaimClient({ origin, fetcher }).complete(
        { token, factor: 'webauthn', assertion: { private: 'x'.repeat(65536) } },
        signal(),
        sent
      )
    ).rejects.toMatchObject({ code: 'invalid_request', uncertain: false });
    expect(fetcher).not.toHaveBeenCalled();
    expect(sent).not.toHaveBeenCalled();
  });

  it.each([401, 429, 503])(
    'preserves opaque errors after %i and does not retry submitted factors',
    async (status) => {
      const fetcher = jest
        .fn()
        .mockResolvedValue(json({ error: 'invalid_token', detail: token }, status));
      await expect(
        new ReclaimClient({ origin, fetcher }).complete(
          { token, factor: 'totp', code: '012345' },
          signal()
        )
      ).rejects.toMatchObject({
        code: 'invalid_token',
        message: 'invalid_token',
        uncertain: status >= 500,
      });
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
  );

  it('does not add DPoP or replay even if an anonymous endpoint returns a nonce challenge', async () => {
    const fetcher = jest.fn().mockResolvedValue(
      json({ error: 'use_dpop_nonce' }, 401, {
        'DPoP-Nonce': 'nonce',
        'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
      })
    );
    await expect(
      new ReclaimClient({ origin, fetcher }).options(token, signal())
    ).rejects.toMatchObject({ code: 'use_dpop_nonce' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('reports lost or unreadable completion responses as uncertain without retaining transport secrets', async () => {
    const proof: ReclaimProof = { token, factor: 'totp', code: '012345' };
    const fetcher = jest.fn().mockRejectedValue(new Error(`private ${token}`));
    await expect(
      new ReclaimClient({ origin, fetcher }).complete(proof, signal())
    ).rejects.toMatchObject({ code: 'network_error', message: 'network_error', uncertain: true });
    expect(fetcher).toHaveBeenCalledTimes(1);
    for (const status of [200, 502]) {
      const invalid = jest.fn().mockResolvedValue(new Response('gateway detail', { status }));
      await expect(
        new ReclaimClient({ origin, fetcher: invalid }).complete(proof, signal())
      ).rejects.toMatchObject({ uncertain: true });
      expect(invalid).toHaveBeenCalledTimes(1);
    }
  });

  it('distinguishes pre-send cancellation from post-send uncertainty, and applies a bounded timeout', async () => {
    jest.useFakeTimers();
    const fetcher = jest.fn(
      (_url, request: RequestInit = {}) =>
        new Promise<Response>((_resolve, reject) => {
          request.signal?.addEventListener(
            'abort',
            () => reject(new DOMException('aborted', 'AbortError')),
            { once: true }
          );
        })
    );
    const client = new ReclaimClient({ origin, fetcher });
    const proof: ReclaimProof = { token, factor: 'totp', code: '012345' };
    try {
      const before = new AbortController();
      before.abort();
      await expect(client.complete(proof, before.signal)).rejects.toMatchObject({
        name: 'AbortError',
      });
      expect(fetcher).not.toHaveBeenCalled();
      const during = new AbortController();
      const request = client.complete(proof, during.signal);
      const rejected = expect(request).rejects.toMatchObject({ uncertain: true });
      during.abort();
      await rejected;
      expect(fetcher).toHaveBeenCalledTimes(1);
      const timeout = client.complete(proof, signal());
      const timedOut = expect(timeout).rejects.toMatchObject({ uncertain: true });
      jest.advanceTimersByTime(20001);
      await timedOut;
      expect(fetcher).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });
});
