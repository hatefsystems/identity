import { PortalError } from './errors';
import {
  boolean,
  identifier,
  integer,
  list,
  normalizeName,
  record,
  text,
  timestamp,
} from './validation';

export type Profile = {
  id: string;
  email: string;
  display_name: string;
  status: string;
  lifecycle_revision: string;
  session: { id: string; expires_at: string };
};

export function profileResponse(value: unknown): Profile {
  const profile = record(value);
  const session = record(profile.session);
  const revision = text(profile.lifecycle_revision, 19);
  if (!/^(0|[1-9][0-9]*)$/.test(revision) || BigInt(revision) > 9223372036854775807n)
    throw new PortalError('invalid_response');
  const name = text(profile.display_name, 160);
  if (normalizeName(name) !== name) throw new PortalError('invalid_response');
  return {
    id: identifier(profile.id),
    email: text(profile.email, 320),
    display_name: name,
    status: text(profile.status, 64),
    lifecycle_revision: revision,
    session: { id: identifier(session.id), expires_at: timestamp(session.expires_at) },
  };
}

export type Passkey = {
  id: string;
  name: string;
  created_at: string;
  last_used_at?: string;
  user_verified: boolean;
  backup_eligible: boolean;
  backup_state: boolean;
};

export function passkeyResponse(value: unknown): Passkey {
  const item = record(value);
  const name = text(item.name, 160);
  if (normalizeName(name) !== name) throw new PortalError('invalid_response');
  return {
    id: identifier(item.id, 1400),
    name,
    created_at: timestamp(item.created_at),
    last_used_at: item.last_used_at == null ? undefined : timestamp(item.last_used_at),
    user_verified: boolean(item.user_verified),
    backup_eligible: boolean(item.backup_eligible),
    backup_state: boolean(item.backup_state),
  };
}

export type BrowserSession = {
  id: string;
  current: boolean;
  ip: string;
  user_agent: string;
  created_at: string;
  last_seen_at: string;
};

export function sessionsResponse(value: unknown): BrowserSession[] {
  return list(value, (entry) => {
    const item = record(entry);
    return {
      id: identifier(item.id),
      current: boolean(item.current),
      // Untrusted metadata is rendered as text, bounded, never interpreted as a
      // device model or a verified location.
      ip: text(item.ip ?? '', 8192).slice(0, 64),
      user_agent: Array.from(text(item.user_agent ?? '', 8192))
        .slice(0, 240)
        .join(''),
      created_at: timestamp(item.created_at),
      last_seen_at: timestamp(item.last_seen_at),
    };
  });
}

export type RecoveryStatus = { remaining: number; low: boolean };
export function recoveryStatusResponse(value: unknown): RecoveryStatus {
  const item = record(value);
  return { remaining: integer(item.remaining), low: boolean(item.low) };
}

export type RecoveryBatch = { codes: string[]; count: number };
export function recoveryBatchResponse(value: unknown): RecoveryBatch {
  const item = record(value);
  const codes = list(
    item.codes,
    (value) => {
      const code = text(value, 128);
      if (!/^[A-Za-z0-9-]{16,128}$/.test(code)) throw new PortalError('invalid_response');
      return code;
    },
    100
  );
  const count = integer(item.count, 100);
  if (count === 0 || count !== codes.length || new Set(codes).size !== count)
    throw new PortalError('invalid_response');
  return { codes, count };
}

export function stepUpChallengeResponse(value: unknown) {
  const item = record(value);
  const methods = list(item.methods, (method) => text(method, 32), 10).filter(
    (method): method is 'webauthn' | 'totp' => method === 'webauthn' || method === 'totp'
  );
  if (methods.length === 0 || (methods.includes('webauthn') && !item.webauthn))
    throw new PortalError('no_stepup_factor');
  return { methods, webauthn: item.webauthn };
}

export type StepUpChallenge = ReturnType<typeof stepUpChallengeResponse>;

export class StepUpGrant {
  #token: string | undefined;
  constructor(
    value: unknown,
    private readonly sessionID: string,
    requestedAt: number,
    sessionDeadline: number
  ) {
    const item = record(value);
    if (item.token_type !== 'StepUp') throw new PortalError('invalid_response');
    this.#token = text(item.token, 2048);
    if (!this.#token || /\s/.test(this.#token)) throw new PortalError('invalid_response');
    this.deadline = Math.min(requestedAt + integer(item.expires_in, 600) * 1000, sessionDeadline);
  }
  private readonly deadline: number;

  take(sessionID: string): string {
    const token = this.#token;
    this.#token = undefined;
    if (!token || sessionID !== this.sessionID || Date.now() >= this.deadline)
      throw new PortalError('grant_expired');
    return token;
  }

  clear(): void {
    this.#token = undefined;
  }
}
