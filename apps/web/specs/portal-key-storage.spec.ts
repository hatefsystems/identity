/** @jest-environment node */

import { webcrypto } from 'node:crypto';
import { browserKey, type BrowserKey } from '../app/_lib/portal/dpop';

// This transaction adapter exercises the real initialization code and real
// structured-cloned CryptoKeys. Multi-tab browser/IndexedDB implementation
// behavior is additionally covered by the production browser acceptance suite.
type Request = {
  result?: unknown;
  onsuccess?: () => void;
  onerror?: () => void;
  onblocked?: () => void;
  onupgradeneeded?: () => void;
};
function keyDatabase() {
  const entries = new Map<string, BrowserKey>();
  const writes: BrowserKey[] = [];
  let tail = Promise.resolve();
  let failWrites = false;
  let blocked = false;
  const db = {
    objectStoreNames: { contains: () => true },
    close: jest.fn(),
    onversionchange: undefined,
    transaction: jest.fn((_name: string, mode: string) => {
      const operations: (() => void)[] = [];
      let aborted = false;
      let release!: () => void;
      const previous = tail;
      tail = new Promise<void>((resolve) => {
        release = resolve;
      });
      const transaction = {
        oncomplete: undefined as (() => void) | undefined,
        onabort: undefined as (() => void) | undefined,
        onerror: undefined as (() => void) | undefined,
        abort() {
          if (!aborted) {
            aborted = true;
            transaction.onabort?.();
            release();
          }
        },
        objectStore: () => ({
          get(key: string) {
            const request: Request = {};
            operations.push(() => {
              request.result = structuredClone(entries.get(key));
              request.onsuccess?.();
            });
            return request;
          },
          add(value: BrowserKey, key: string) {
            if (mode !== 'readwrite') throw new Error('Read-only write');
            operations.push(() => {
              if (failWrites || entries.has(key)) {
                transaction.abort();
                return;
              }
              const clone = structuredClone(value);
              entries.set(key, clone);
              writes.push(clone);
            });
          },
        }),
      };
      void previous.then(() => {
        function next() {
          if (aborted) return;
          const operation = operations.shift();
          if (operation) {
            operation();
            queueMicrotask(next);
          } else {
            transaction.oncomplete?.();
            release();
          }
        }
        next();
      });
      return transaction;
    }),
  };
  const factory = {
    open: jest.fn(() => {
      const request: Request = { result: db };
      queueMicrotask(() => {
        if (blocked) request.onblocked?.();
        else request.onsuccess?.();
      });
      return request;
    }),
  };
  return {
    factory,
    entries,
    writes,
    db,
    failWrites: () => {
      failWrites = true;
    },
    block: () => {
      blocked = true;
    },
  };
}

let storage: ReturnType<typeof keyDatabase>;
const originals = ['crypto', 'indexedDB', 'isSecureContext'].map(
  (name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)] as const
);
beforeEach(() => {
  storage = keyDatabase();
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  Object.defineProperty(globalThis, 'indexedDB', { configurable: true, value: storage.factory });
  Object.defineProperty(globalThis, 'isSecureContext', { configurable: true, value: true });
});
afterEach(() => {
  jest.restoreAllMocks();
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else Reflect.deleteProperty(globalThis, name);
  }
});

describe('non-exportable browser key initialization', () => {
  it('chooses one transaction winner under concurrent initialization and only exports public material', async () => {
    const exportKey = jest.spyOn(crypto.subtle, 'exportKey');
    const values = await Promise.all([browserKey(true), browserKey(true), browserKey(true)]);
    expect(storage.writes).toHaveLength(1);
    expect(storage.factory.open).toHaveBeenCalledWith('hatef-portal-dpop', 1);
    expect(values[0].publicJwk).toEqual(values[1].publicJwk);
    expect(values[1].publicJwk).toEqual(values[2].publicJwk);
    expect(Object.keys(storage.writes[0]).sort()).toEqual(['privateKey', 'publicJwk']);
    for (const call of exportKey.mock.calls) expect((call[1] as CryptoKey).type).toBe('public');
    exportKey.mockRestore();
    for (const key of values) {
      expect(key.privateKey.extractable).toBe(false);
      expect(key.privateKey.usages).toEqual(['sign']);
      await expect(crypto.subtle.exportKey('jwk', key.privateKey)).rejects.toThrow();
    }
    expect(storage.db.transaction).toHaveBeenCalledWith('keys', 'readwrite');
  });

  it('never invents a key during protected bootstrap and detects deletion rather than using a memory fallback', async () => {
    const generate = jest.spyOn(crypto.subtle, 'generateKey');
    await expect(browserKey()).rejects.toMatchObject({ code: 'key_unavailable' });
    expect(generate).not.toHaveBeenCalled();
    await browserKey(true);
    generate.mockClear();
    storage.entries.clear();
    await expect(browserKey(false)).rejects.toMatchObject({ code: 'key_unavailable' });
    expect(generate).not.toHaveBeenCalled();
  });

  it('fails closed on blocked/failed persistence without storing credential strings', async () => {
    storage.failWrites();
    await expect(browserKey(true)).rejects.toMatchObject({ code: 'key_unavailable' });
    expect(storage.entries.size).toBe(0);
    storage.block();
    await expect(browserKey(true)).rejects.toMatchObject({ code: 'key_unavailable' });
  });

  it('rejects extractable or mismatched stored keys rather than silently replacing their binding', async () => {
    const good = await browserKey(true);
    const different = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );
    storage.entries.set('active', { ...good, privateKey: different.privateKey });
    await expect(browserKey(true)).rejects.toMatchObject({ code: 'key_unavailable' });
    const exportable = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    storage.entries.set('active', { ...good, privateKey: exportable.privateKey });
    await expect(browserKey(true)).rejects.toMatchObject({ code: 'key_unavailable' });
    expect(storage.writes).toHaveLength(1);
  });
});
