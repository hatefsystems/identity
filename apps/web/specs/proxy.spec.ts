/** @jest-environment node */

import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { unstable_doesMiddlewareMatch } from 'next/experimental/testing/server';
import { config, proxy } from '../proxy';

describe('CSP proxy', () => {
  beforeEach(() => {
    jest.replaceProperty(process, 'env', { ...process.env, NODE_ENV: 'production' });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('uses a fresh 256-bit cryptographic nonce for each request', () => {
    const randomBytes = jest.spyOn(crypto, 'randomBytes');
    const request = new NextRequest('https://identity.example/');
    const first = proxy(request);
    const second = proxy(request);
    const nonce = first.headers.get('x-middleware-request-x-nonce') ?? '';

    expect(randomBytes).toHaveBeenCalledWith(32);
    expect(randomBytes).toHaveBeenCalledTimes(2);
    expect(nonce).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(Buffer.from(nonce, 'base64')).toHaveLength(32);
    expect(second.headers.get('x-middleware-request-x-nonce')).not.toBe(nonce);
    expect(first.headers.get('x-nonce')).toBeNull();
  });

  it('forwards the same enforced policy to the renderer and browser', () => {
    const response = proxy(new NextRequest('https://identity.example/'));
    const nonce = response.headers.get('x-middleware-request-x-nonce');
    const policy = response.headers.get('Content-Security-Policy') ?? '';

    expect(policy.split('; ')).toEqual([
      "default-src 'self'",
      `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
      "script-src-attr 'none'",
      `style-src 'self' 'nonce-${nonce}'`,
      "style-src-attr 'none'",
      "connect-src 'self'",
      "img-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "frame-src 'none'",
      'upgrade-insecure-requests',
    ]);
    expect(response.headers.get('x-middleware-request-content-security-policy')).toBe(policy);
    expect(response.headers.get('Cache-Control')).toBe('private, no-store');
    expect(response.headers.get('Content-Security-Policy-Report-Only')).toBeNull();
    expect(policy).not.toMatch(/[\r\n]|unsafe-inline|unsafe-eval|trusted-types/);
  });

  it('overwrites caller-controlled security headers without leaking other headers', () => {
    const request = new NextRequest('https://identity.example/account', {
      headers: {
        'x-nonce': 'attacker',
        'Content-Security-Policy': "script-src * 'unsafe-inline'",
        cookie: 'session=test-session',
        authorization: 'Bearer test-token',
        'x-request-id': 'test-request',
      },
    });
    const response = proxy(request);

    expect(response.headers.get('Content-Security-Policy')).not.toContain('attacker');
    expect(response.headers.get('x-middleware-request-x-nonce')).not.toBe('attacker');
    expect(response.headers.get('x-middleware-request-cookie')).toBe('session=test-session');
    expect(response.headers.get('x-middleware-request-authorization')).toBe('Bearer test-token');
    expect(response.headers.get('x-middleware-request-x-request-id')).toBe('test-request');
    expect(response.headers.get('cookie')).toBeNull();
    expect(response.headers.get('authorization')).toBeNull();
    expect(response.headers.get('x-request-id')).toBeNull();
    expect(request.headers.get('x-nonce')).toBe('attacker');
  });

  it('permits development tooling only in development', () => {
    jest.replaceProperty(process, 'env', { ...process.env, NODE_ENV: 'development' });
    const response = proxy(new NextRequest('http://localhost:3000/'));
    const nonce = response.headers.get('x-middleware-request-x-nonce');
    const policy = response.headers.get('Content-Security-Policy') ?? '';

    expect(policy).toContain(`script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'`);
    expect(policy).toContain("script-src-attr 'none'");
    expect(policy).toContain("style-src 'self' 'unsafe-inline'");
    expect(policy).not.toContain('style-src-attr');
    expect(policy).not.toContain(`style-src 'self' 'nonce-${nonce}'`);
    expect(policy).toContain("connect-src 'self' ws: wss:");
    expect(policy).not.toContain('upgrade-insecure-requests');
    expect(response.headers.get('x-middleware-request-content-security-policy')).toBe(policy);
  });

  it('does not relax the policy in test mode', () => {
    jest.replaceProperty(process, 'env', { ...process.env, NODE_ENV: 'test' });
    const policy = proxy(new NextRequest('https://identity.example/')).headers.get(
      'Content-Security-Policy'
    );

    expect(policy).not.toMatch(/unsafe-inline|unsafe-eval|ws:/);
    expect(policy).toContain("style-src-attr 'none'");
    expect(policy).toContain('upgrade-insecure-requests');
  });

  it('does not continue with a weak nonce when secure randomness fails', () => {
    jest.spyOn(crypto, 'randomBytes').mockImplementationOnce(() => {
      throw new Error('randomness unavailable');
    });

    expect(() => proxy(new NextRequest('https://identity.example/'))).toThrow(
      'randomness unavailable'
    );
  });
});

describe('CSP route coverage', () => {
  it.each([
    '/',
    '/login',
    '/account/security',
    '/oauth2/authorize',
    '/oauth2/error',
    '/apiary',
    '/_next/static-page',
    '/_next/image-preview',
    '/favicon.ico/extra',
    '/favicon.ico.fake',
    '/users/alice@example.com',
    '/missing.json?query=1',
  ])('protects document route %s', (url) => {
    expect(unstable_doesMiddlewareMatch({ config, url })).toBe(true);
  });

  it.each([
    '/api',
    '/api/v1/profile',
    '/_next/static',
    '/_next/static/chunks/app.js',
    '/_next/image',
    '/_next/image?url=%2Ficon.png&w=32&q=75',
    '/favicon.ico',
    '/favicon.ico?version=1',
  ])('does not apply document nonce/cache policy to %s', (url) => {
    expect(unstable_doesMiddlewareMatch({ config, url })).toBe(false);
  });

  it.each([
    { 'next-router-prefetch': '1' },
    { purpose: 'prefetch' },
    { 'sec-purpose': 'prefetch' },
    { rsc: '1', 'next-router-prefetch': '1' },
  ])('does not bypass protection for request headers %j', (headers) => {
    expect(unstable_doesMiddlewareMatch({ config, url: '/', headers })).toBe(true);
  });
});
