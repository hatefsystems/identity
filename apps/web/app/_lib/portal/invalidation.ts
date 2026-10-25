const channelName = 'hatef-portal-session';
let channel: BroadcastChannel | null = null;
const listeners = new Set<() => void>();

function documentChannel(): BroadcastChannel | null {
  if (channel) return channel;
  if (typeof BroadcastChannel === 'undefined') return null;
  try {
    channel = new BroadcastChannel(channelName);
    channel.onmessage = (event) => {
      if (event.data === 'invalidate') for (const listener of listeners) listener();
    };
    return channel;
  } catch {
    return null;
  }
}

export function invalidateOtherTabs(): void {
  try {
    // Never broadcast an account, session identifier, key, nonce, grant, or code.
    // BroadcastChannel excludes its sending object, not its sending document.
    // Publishing through the listener's object prevents same-document self-echo.
    documentChannel()?.postMessage('invalidate');
  } catch {
    // Session intent checks and foreground bootstrap still fail closed when
    // browser policy disables messaging. Do not fall back to persistent data.
  }
}

export function onOtherTabInvalidation(listener: () => void): () => void {
  if (!documentChannel()) return () => undefined;
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      channel?.close();
      channel = null;
    }
  };
}

export const sensitiveClearEvent = 'portal-sensitive-clear';
export const sensitiveSuspendEvent = 'portal-sensitive-suspend';
export function clearSensitiveViews(): void {
  window.dispatchEvent(new Event(sensitiveClearEvent));
}

export function suspendSensitiveViews(): void {
  window.dispatchEvent(new Event(sensitiveSuspendEvent));
}
