import { PortalError, throwIfAborted } from './errors';

export const emptyResponse = (value: unknown): void => {
  if (value !== undefined) throw new PortalError('invalid_response');
};
const responseLimit = 256 * 1024;

export async function readResponse(response: Response, signal: AbortSignal): Promise<unknown> {
  if (response.status === 204) return undefined;
  const length = response.headers.get('Content-Length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > responseLimit)) {
    await response.body?.cancel();
    throw new PortalError('invalid_response');
  }
  if (
    !/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') ||
    !response.body
  ) {
    await response.body?.cancel();
    throw new PortalError('invalid_response');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      throwIfAborted(signal);
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > responseLimit) {
        await reader.cancel();
        throw new PortalError('invalid_response');
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally {
    reader.releaseLock();
  }
}
