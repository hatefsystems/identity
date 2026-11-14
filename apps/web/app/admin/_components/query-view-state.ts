'use client';

import { useEffect, useRef, useState, type FocusEvent } from 'react';
import type { MessageDescriptor } from '../../../i18n/messages';
import { PortalError } from '../../_lib/portal/errors';
import { sensitiveClearEvent, sensitiveSuspendEvent } from '../../_lib/portal/invalidation';

class QueryWork {
  private controller: AbortController | null = null;
  blocked = false;

  begin(): AbortController | null {
    if (this.blocked || document.visibilityState === 'hidden') return null;
    this.cancel();
    this.controller = new AbortController();
    return this.controller;
  }

  current(controller: AbortController): boolean {
    return (
      !this.blocked &&
      document.visibilityState !== 'hidden' &&
      this.controller === controller &&
      !controller.signal.aborted
    );
  }

  finish(controller: AbortController): void {
    if (this.controller === controller) this.controller = null;
  }

  cancel(): void {
    this.controller?.abort();
    this.controller = null;
  }
}

// The provider revalidates and remounts private children. This boundary also
// discards view state immediately, including when a transport ignores abort.
export function useQueryViewWork(clearView: () => void) {
  const [work] = useState(() => new QueryWork());
  const [cleared, setCleared] = useState(false);
  const latestClear = useRef(clearView);
  useEffect(() => {
    latestClear.current = clearView;
  });
  useEffect(() => {
    work.blocked = false;
    function clear() {
      work.blocked = true;
      work.cancel();
      latestClear.current();
      setCleared(true);
    }
    function visibility() {
      if (document.visibilityState === 'hidden') clear();
    }
    const events = [sensitiveClearEvent, sensitiveSuspendEvent, 'pagehide', 'popstate'];
    for (const event of events) window.addEventListener(event, clear);
    document.addEventListener('visibilitychange', visibility);
    return () => {
      work.blocked = true;
      work.cancel();
      for (const event of events) window.removeEventListener(event, clear);
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [work]);
  return { work, cleared };
}

export function queryPageSize(value: string, maximum: number): number | null {
  if (value.trim() !== value || !/^[1-9][0-9]{0,2}$/.test(value)) return null;
  const size = Number(value);
  return size <= maximum ? size : null;
}

export function queryFailureMessage(failure: unknown): MessageDescriptor {
  if (failure instanceof PortalError) {
    if (failure.status === 403) return { key: 'audit.failure.denied' };
    if (failure.status === 429 || failure.code === 'rate_limited')
      return failure.retryAfterSeconds !== undefined
        ? { key: 'audit.failure.retryAfter', values: { seconds: failure.retryAfterSeconds } }
        : { key: 'audit.failure.rateLimited' };
    if (failure.code === 'invalid_response') return { key: 'audit.failure.invalidResponse' };
    if (['unknown_seq', 'invalid_request', 'window_too_large'].includes(failure.code))
      return { key: 'audit.failure.rejected' };
    if (failure.code === 'missing_head') return { key: 'audit.failure.missingHead' };
    if (failure.status === 404) return { key: 'audit.failure.unavailable' };
    if (failure.status === 401 || failure.code === 'session_changed')
      return { key: 'audit.failure.session' };
    if (
      failure.status >= 500 ||
      ['audit_unavailable', 'service_unavailable', 'rate_limit_unavailable'].includes(failure.code)
    )
      return { key: 'audit.failure.service' };
  }
  return { key: 'audit.failure.unknown' };
}

export const querySelectClass =
  'min-h-11 w-full min-w-0 max-w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:opacity-50';
export const queryTableFrameClass =
  'min-w-0 max-w-full scroll-m-2 overflow-x-auto rounded-lg border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2';

export function revealQueryFocus(event: FocusEvent<HTMLDivElement>) {
  // Nearest alignment can clip a viewport-fitting frame by its scroll margin.
  const center = event.target === event.currentTarget &&
    event.currentTarget.getBoundingClientRect().height <= window.innerHeight;
  event.target.scrollIntoView({ block: center ? 'center' : 'nearest', inline: 'nearest' });
}
export const queryCellClass = 'px-3 py-2 text-start align-top text-sm';
export const queryHeadClass = 'px-3 py-3 text-start text-xs font-semibold text-muted-foreground';
export const queryClearedMessage: MessageDescriptor = { key: 'audit.privateCleared' };
