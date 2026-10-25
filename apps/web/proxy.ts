import { randomBytes } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';

export function proxy(request: NextRequest) {
  const nonce = randomBytes(32).toString('base64');
  const isDevelopment = process.env.NODE_ENV === 'development';
  const policy = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDevelopment ? " 'unsafe-eval'" : ''}`,
    "script-src-attr 'none'",
    `style-src 'self' ${isDevelopment ? "'unsafe-inline'" : `'nonce-${nonce}'`}`,
    ...(!isDevelopment ? ["style-src-attr 'none'"] : []),
    `connect-src 'self'${isDevelopment ? ' ws: wss:' : ''}`,
    "img-src 'self'",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "frame-src 'none'",
    ...(!isDevelopment ? ['upgrade-insecure-requests'] : []),
  ].join('; ');

  const headers = new Headers(request.headers);
  headers.set('x-nonce', nonce);
  // Next reads the request CSP to nonce its bootstrap and Flight scripts.
  headers.set('Content-Security-Policy', policy);

  const response = NextResponse.next({ request: { headers } });
  response.headers.set('Content-Security-Policy', policy);
  response.headers.set('Cache-Control', 'private, no-store');
  response.headers.set('Referrer-Policy', 'no-referrer');
  return response;
}

export const config = {
  // Keep document routes (including dotted URLs and prefetches) protected.
  matcher: ['/((?!api(?:/|$)|_next/static(?:/|$)|_next/image(?:/|$)|favicon\\.ico$).*)'],
};
