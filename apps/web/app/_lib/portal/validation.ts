import { PortalError } from './errors';

export function normalizeName(value: string): string {
  // Go's UTF-8 validator rejects lone surrogates after JSON decoding. Match its
  // control/line-separator policy before trimming, including at either edge.
  if (/[\p{Cc}\p{Cs}\u2028\u2029]/u.test(value))
    throw new Error('Use a single line without control characters.');
  const trimmed = value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '');
  if (Array.from(trimmed).length > 80) throw new Error('Use at most 80 characters.');
  return trimmed;
}

export function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new PortalError('invalid_response');
  return value as Record<string, unknown>;
}

export function text(value: unknown, max = 256): string {
  if (typeof value !== 'string' || value.length > max) throw new PortalError('invalid_response');
  return value;
}

export function identifier(value: unknown, max = 256): string {
  const result = text(value, max);
  if (!/^[A-Za-z0-9_-]+$/.test(result)) throw new PortalError('invalid_response');
  return result;
}

export function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new PortalError('invalid_response');
  return value;
}

export function integer(value: unknown, max = 10000): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max)
    throw new PortalError('invalid_response');
  return value as number;
}

export function timestamp(value: unknown): string {
  const result = text(value, 64);
  if (
    !/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(result) ||
    !Number.isFinite(Date.parse(result))
  )
    throw new PortalError('invalid_response');
  return result;
}

export function list<T>(value: unknown, decode: (item: unknown) => T, max = 1000): T[] {
  if (!Array.isArray(value) || value.length > max) throw new PortalError('invalid_response');
  return value.map(decode);
}

export function safeReturnPath(value: string | null): string {
  return [
    '/dashboard',
    '/dashboard/profile',
    '/dashboard/security',
    '/dashboard/sessions',
  ].includes(value ?? '')
    ? (value as string)
    : '/dashboard';
}
