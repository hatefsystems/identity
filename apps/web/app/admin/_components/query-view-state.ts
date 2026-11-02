'use client';

import { useEffect, useRef, useState, type FocusEvent } from 'react';
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

export function queryFailureMessage(failure: unknown): string {
  if (failure instanceof PortalError) {
    if (failure.status === 403)
      return 'Administrative access was denied. Private results were cleared; your normal account session has not been signed out.';
    if (failure.status === 429 || failure.code === 'rate_limited')
      return failure.retryAfterSeconds !== undefined
        ? `Request rate limited. Wait ${failure.retryAfterSeconds} seconds before another explicit request. Nothing will retry automatically.`
        : 'Request rate limited. Try again later with an explicit request. Nothing will retry automatically.';
    if (failure.code === 'invalid_response')
      return 'The response was malformed, oversized, or inconsistent with this request. No new result was accepted.';
    if (
      failure.code === 'unknown_seq' ||
      failure.code === 'invalid_request' ||
      failure.code === 'window_too_large'
    )
      return 'The requested query or verification boundary was rejected. Review the inputs and start a new query or run.';
    if (failure.code === 'missing_head')
      return 'Verification state is missing. This is not evidence of an intact or empty chain. Start a new run only after the service is available.';
    if (failure.status === 404)
      return 'This administrative endpoint is unavailable on this deployment. No result was returned.';
    if (failure.status === 401 || failure.code === 'session_changed')
      return 'The session is no longer available. Private results were cleared; check the current session before continuing.';
    if (
      failure.status >= 500 ||
      ['audit_unavailable', 'service_unavailable', 'rate_limit_unavailable'].includes(failure.code)
    )
      return 'The service could not return an audited result. No new result was accepted; this is not an empty result or an integrity finding.';
  }
  return 'The request could not be completed. No new result was accepted. Check the connection before another explicit request.';
}

export const querySelectClass =
  'min-h-11 w-full min-w-0 max-w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:opacity-50';
export const queryTableFrameClass =
  'min-w-0 max-w-full scroll-m-2 overflow-x-auto rounded-lg border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2';

export function revealQueryFocus(event: FocusEvent<HTMLDivElement>) {
  event.target.scrollIntoView({ block: 'nearest', inline: 'nearest' });
}
export const queryCellClass = 'px-3 py-2 text-left align-top text-sm';
export const queryHeadClass = 'px-3 py-3 text-left text-xs font-semibold text-muted-foreground';
export const queryClearedMessage =
  'Private query data was cleared. Session and administrative access must be checked again before continuing.';
