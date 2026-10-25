import { PortalError, throwIfAborted } from './errors';
import { base64url } from './webauthn';

export type BrowserKey = {
  privateKey: CryptoKey;
  publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
};

const database = 'hatef-portal-dpop';
const store = 'keys';

function openKeys(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const request = indexedDB.open(database, 1);
    const timer = setTimeout(fail, 5000);
    function fail() {
      settled = true;
      clearTimeout(timer);
      reject(new PortalError('key_unavailable'));
    }
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(store)) request.result.createObjectStore(store);
    };
    request.onblocked = fail;
    request.onerror = fail;
    request.onsuccess = () => {
      clearTimeout(timer);
      if (settled) request.result.close();
      else {
        settled = true;
        request.result.onversionchange = () => request.result.close();
        resolve(request.result);
      }
    };
  });
}

async function storedKey(candidate?: BrowserKey): Promise<BrowserKey | undefined> {
  const db = await openKeys();
  try {
    return await new Promise<BrowserKey | undefined>((resolve, reject) => {
      // Key generation must happen BEFORE this transaction. Awaiting Web Crypto
      // inside it would auto-commit the transaction and lose the cross-tab lock.
      const transaction = db.transaction(store, candidate ? 'readwrite' : 'readonly');
      const keys = transaction.objectStore(store);
      let selected: BrowserKey | undefined;
      const timer = setTimeout(() => {
        try {
          transaction.abort();
        } catch {
          /* Already completed. */
        }
        reject(new PortalError('key_unavailable'));
      }, 5000);
      transaction.onabort = transaction.onerror = () => {
        clearTimeout(timer);
        reject(new PortalError('key_unavailable'));
      };
      transaction.oncomplete = () => {
        clearTimeout(timer);
        resolve(selected);
      };
      const request = keys.get('active');
      request.onsuccess = () => {
        selected = request.result;
        if (selected === undefined && candidate) {
          selected = candidate;
          keys.add(candidate, 'active');
        }
      };
    });
  } finally {
    db.close();
  }
}

async function validateKey(value: BrowserKey): Promise<BrowserKey> {
  const key = value?.privateKey;
  const jwk = value?.publicJwk;
  const algorithm = key?.algorithm as EcKeyAlgorithm | undefined;
  if (
    !key ||
    key.type !== 'private' ||
    key.extractable ||
    algorithm?.name !== 'ECDSA' ||
    algorithm.namedCurve !== 'P-256' ||
    key.usages.length !== 1 ||
    key.usages[0] !== 'sign' ||
    jwk?.kty !== 'EC' ||
    jwk.crv !== 'P-256' ||
    !/^[A-Za-z0-9_-]{43}$/.test(jwk.x) ||
    !/^[A-Za-z0-9_-]{43}$/.test(jwk.y) ||
    'd' in jwk
  )
    throw new PortalError('key_unavailable');
  const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
  const probe = crypto.getRandomValues(new Uint8Array(32));
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, probe);
  if (
    !(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, probe))
  )
    throw new PortalError('key_unavailable');
  return { privateKey: key, publicJwk };
}

export async function browserKey(initialize = false, signal?: AbortSignal): Promise<BrowserKey> {
  throwIfAborted(signal);
  try {
    if (!globalThis.isSecureContext || !globalThis.indexedDB || !globalThis.crypto?.subtle)
      throw new PortalError('key_unavailable');
    let selected = await storedKey();
    if (!selected && initialize) {
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
        'sign',
        'verify',
      ]);
      const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
      if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string')
        throw new PortalError('key_unavailable');
      throwIfAborted(signal);
      await storedKey({
        privateKey: pair.privateKey,
        publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
      });
      // Verify the actual persisted structured clone, not just the candidate.
      selected = await storedKey();
    }
    if (!selected) throw new PortalError('key_unavailable');
    const usable = await validateKey(selected);
    throwIfAborted(signal);
    return usable;
  } catch {
    throwIfAborted(signal);
    throw new PortalError('key_unavailable');
  }
}

export async function signProof(
  key: BrowserKey,
  method: string,
  url: string,
  nonce?: string
): Promise<string> {
  const encode = (value: unknown) => base64url(new TextEncoder().encode(JSON.stringify(value)));
  const header = encode({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.publicJwk });
  const payload = encode({
    jti: crypto.randomUUID(),
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    ...(nonce ? { nonce } : {}),
  });
  const input = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key.privateKey,
    new TextEncoder().encode(input)
  );
  return `${input}.${base64url(signature)}`;
}
