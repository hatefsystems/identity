import { PortalError, throwIfAborted } from './errors';

export const emptyResponse = (value: unknown): void => {
  if (value !== undefined) throw new PortalError('invalid_response');
};
const defaultResponseLimit = 256 * 1024;

export async function readResponse(
  response: Response,
  signal: AbortSignal,
  responseLimit = defaultResponseLimit
): Promise<unknown> {
  if (signal.aborted) await response.body?.cancel().catch(() => undefined);
  throwIfAborted(signal);
  const length = response.headers.get('Content-Length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > responseLimit)) {
    await response.body?.cancel().catch(() => undefined);
    throw new PortalError('invalid_response');
  }
  const empty = response.status === 204;
  if (empty) {
    if (length !== null && Number(length) !== 0) {
      await response.body?.cancel().catch(() => undefined);
      throw new PortalError('invalid_response');
    }
    if (!response.body) return undefined;
  }
  if (
    (!empty && !/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) ||
    !response.body
  ) {
    await response.body?.cancel().catch(() => undefined);
    throw new PortalError('invalid_response');
  }
  const reader = response.body.getReader();
  const abort = () => {
    void reader.cancel().catch(() => undefined);
  };
  signal.addEventListener('abort', abort, { once: true });
  // Bound retained memory as well as bytes, even if a response arrives in many
  // tiny chunks. The client selects the ceiling only for exact allowlisted routes.
  // Chromium can expose an empty stream for 204. Verify zero bytes rather than
  // assuming Response.body is null; any non-empty chunk is still rejected.
  const bytes = new Uint8Array(empty ? 0 : responseLimit);
  let size = 0;
  try {
    for (;;) {
      throwIfAborted(signal);
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > bytes.byteLength) {
        await reader.cancel().catch(() => undefined);
        throw new PortalError('invalid_response');
      }
      bytes.set(value, size - value.byteLength);
    }
    throwIfAborted(signal);
    if (empty) return undefined;
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size)));
    } catch {
      throw new PortalError('invalid_response');
    }
  } finally {
    signal.removeEventListener('abort', abort);
    reader.releaseLock();
  }
}
