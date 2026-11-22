import { PortalError, throwIfAborted } from './errors';
import { list, record, text } from './validation';

export function base64url(value: ArrayBuffer | ArrayBufferView): string {
  const bytes = ArrayBuffer.isView(value)
    ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    : new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unbase64url(value: unknown, max = 65536): ArrayBuffer {
  const encoded = text(value, Math.ceil((max * 4) / 3));
  if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded) || encoded.length % 4 === 1)
    throw new PortalError('invalid_response');
  const binary = atob(encoded.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.length > max || base64url(bytes) !== encoded) throw new PortalError('invalid_response');
  return bytes.buffer;
}

function descriptors(value: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (value === undefined) return undefined;
  return list(value, (item) => {
    const descriptor = record(item);
    if (descriptor.type !== 'public-key') throw new PortalError('invalid_response');
    const transports =
      descriptor.transports === undefined
        ? undefined
        : list(
            descriptor.transports,
            (entry) => {
              if (!['usb', 'nfc', 'ble', 'internal', 'hybrid'].includes(text(entry)))
                throw new PortalError('invalid_response');
              return entry as AuthenticatorTransport;
            },
            5
          );
    return { type: 'public-key', id: unbase64url(descriptor.id, 1024), transports };
  });
}

function timeout(value: unknown): number {
  if (value === undefined) return 60000;
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0)
    throw new PortalError('invalid_response');
  return Math.min(value, 120000);
}

export function assertionOptions(
  value: unknown,
  requireUV = false
): PublicKeyCredentialRequestOptions {
  const options = record(record(value).publicKey);
  const uv = options.userVerification;
  if (uv !== undefined && !['required', 'preferred', 'discouraged'].includes(text(uv)))
    throw new PortalError('invalid_response');
  return {
    challenge: unbase64url(options.challenge),
    rpId: options.rpId === undefined ? undefined : text(options.rpId, 253),
    allowCredentials: descriptors(options.allowCredentials),
    timeout: timeout(options.timeout),
    userVerification: requireUV ? 'required' : (uv as UserVerificationRequirement | undefined),
  };
}

export function creationOptions(value: unknown): PublicKeyCredentialCreationOptions {
  const options = record(record(value).publicKey);
  const user = record(options.user);
  const rp = record(options.rp);
  const selection =
    options.authenticatorSelection === undefined
      ? undefined
      : record(options.authenticatorSelection);
  if (selection) {
    for (const [key, allowed] of Object.entries({
      authenticatorAttachment: ['platform', 'cross-platform'],
      residentKey: ['required', 'preferred', 'discouraged'],
      userVerification: ['required', 'preferred', 'discouraged'],
    })) {
      if (selection[key] !== undefined && !allowed.includes(text(selection[key])))
        throw new PortalError('invalid_response');
    }
    if (
      selection.requireResidentKey !== undefined &&
      typeof selection.requireResidentKey !== 'boolean'
    )
      throw new PortalError('invalid_response');
  }
  if (
    options.attestation !== undefined &&
    !['none', 'indirect', 'direct', 'enterprise'].includes(text(options.attestation))
  )
    throw new PortalError('invalid_response');
  return {
    challenge: unbase64url(options.challenge),
    rp: { id: rp.id === undefined ? undefined : text(rp.id, 253), name: text(rp.name) },
    user: {
      id: unbase64url(user.id, 64),
      name: text(user.name, 1024),
      displayName: text(user.displayName, 1024),
    },
    pubKeyCredParams: list(
      options.pubKeyCredParams,
      (item) => {
        const parameter = record(item);
        if (parameter.type !== 'public-key' || !Number.isSafeInteger(parameter.alg))
          throw new PortalError('invalid_response');
        return { type: 'public-key', alg: parameter.alg as number };
      },
      32
    ),
    excludeCredentials: descriptors(options.excludeCredentials),
    authenticatorSelection: selection as AuthenticatorSelectionCriteria | undefined,
    attestation: options.attestation as AttestationConveyancePreference | undefined,
    timeout: timeout(options.timeout),
    // The portal requests only the non-secret credential-properties extension.
    extensions: { credProps: true },
  };
}

export function firstPasskeyCreationOptions(
  value: unknown,
  origin: string,
  remaining: number
): PublicKeyCredentialCreationOptions {
  const envelope = record(value);
  if (Object.keys(envelope).length !== 2 || !Object.hasOwn(envelope, 'publicKey') ||
    !Object.hasOwn(envelope, 'expires_at')) throw new PortalError('invalid_response');
  const options = creationOptions(value);
  const rpID = options.rp.id;
  const hostname = new URL(origin).hostname;
  const identity = [options.rp.name, options.user.name, options.user.displayName];
  if (!rpID || !/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(rpID) || rpID.length > 253 ||
    (hostname !== rpID && !hostname.endsWith(`.${rpID}`)) ||
    options.user.id.byteLength !== 8 ||
    identity.some((name) => !name || new TextEncoder().encode(name).length > 1024 ||
      /[\p{Cc}\p{Cs}]/u.test(name)) ||
    options.user.name !== options.user.displayName ||
    options.authenticatorSelection?.userVerification !== 'required' ||
    options.pubKeyCredParams.length === 0 ||
    !Number.isFinite(remaining) || remaining <= 0)
    throw new PortalError('invalid_response');
  const serverTimeout = record(envelope.publicKey).timeout;
  if (typeof serverTimeout !== 'number' || !Number.isSafeInteger(serverTimeout) ||
    serverTimeout <= 0 || serverTimeout > 180000) throw new PortalError('invalid_response');
  options.timeout = Math.min(options.timeout ?? serverTimeout, Math.floor(remaining));
  if (options.timeout <= 0) throw new PortalError('invalid_response');
  return options;
}

export function serializeCredential(credential: PublicKeyCredential) {
  if (credential.type !== 'public-key') throw new PortalError('invalid_response');
  const response = credential.response;
  const extensions = credential.getClientExtensionResults();
  const common = {
    id: base64url(credential.rawId),
    rawId: base64url(credential.rawId),
    type: 'public-key',
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: extensions.credProps ? { credProps: extensions.credProps } : {},
  };
  if ('signature' in response) {
    const assertion = response as AuthenticatorAssertionResponse;
    return {
      ...common,
      response: {
        clientDataJSON: base64url(assertion.clientDataJSON),
        authenticatorData: base64url(assertion.authenticatorData),
        signature: base64url(assertion.signature),
        userHandle: assertion.userHandle ? base64url(assertion.userHandle) : null,
      },
    };
  }
  if ('attestationObject' in response) {
    const attestation = response as AuthenticatorAttestationResponse;
    return {
      ...common,
      response: {
        clientDataJSON: base64url(attestation.clientDataJSON),
        attestationObject: base64url(attestation.attestationObject),
        transports: attestation.getTransports?.() ?? [],
      },
    };
  }
  throw new PortalError('invalid_response');
}

export function requireWebAuthn(): void {
  if (
    !globalThis.isSecureContext ||
    typeof PublicKeyCredential === 'undefined' ||
    !navigator.credentials?.get ||
    !navigator.credentials?.create
  )
    throw new PortalError('unsupported');
}

export async function usePasskey(
  value: unknown,
  signal: AbortSignal,
  create = false,
  requireUV = false
) {
  requireWebAuthn();
  throwIfAborted(signal);
  return nativePasskey(
    create ? creationOptions(value) : assertionOptions(value, requireUV), signal, create
  );
}

export function createPasskey(options: PublicKeyCredentialCreationOptions, signal: AbortSignal) {
  return nativePasskey(options, signal, true);
}

async function nativePasskey(
  options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
  signal: AbortSignal,
  create: boolean
) {
  requireWebAuthn();
  throwIfAborted(signal);
  try {
    const credential = create
      ? await navigator.credentials.create({ publicKey: options as PublicKeyCredentialCreationOptions, signal })
      : await navigator.credentials.get({ publicKey: options as PublicKeyCredentialRequestOptions, signal });
    throwIfAborted(signal);
    if (!credential) throw new PortalError('cancelled');
    if (create && !('attestationObject' in (credential as PublicKeyCredential).response))
      throw new PortalError('invalid_response');
    return serializeCredential(credential as PublicKeyCredential);
  } catch (error) {
    throwIfAborted(signal);
    if ((error instanceof Error || error instanceof DOMException) && ['NotAllowedError', 'AbortError'].includes(error.name))
      throw new PortalError('cancelled');
    if ((error instanceof Error || error instanceof DOMException) && error.name === 'SecurityError')
      throw new PortalError('authenticator_security');
    throw error instanceof PortalError ? error : new PortalError('authenticator_failed');
  }
}
