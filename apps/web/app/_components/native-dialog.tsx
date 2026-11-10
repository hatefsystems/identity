'use client';

import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from 'react';
import { cn } from '@hatef/ui';

export function NativeDialog({
  title,
  description,
  children,
  onCancel,
  testId,
  layout = 'default',
  footer,
}: {
  title: string;
  description: ReactNode;
  children: ReactNode;
  onCancel: () => void;
  testId?: string;
  layout?: 'default' | 'review';
  footer?: ReactNode;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const id = useId();

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const element = dialog.current;
    element?.showModal();
    heading.current?.focus();
    return () => {
      element?.close();
      if (opener && isVisible(opener) && isEnabled(opener)) opener.focus();
      else {
        const controls = [...document.querySelectorAll<HTMLElement>(focusableSelector)].filter(
          (control) => isEnabled(control) && isVisible(control)
        );
        const key = opener?.dataset.focusReturn;
        const name = opener?.getAttribute('aria-label') ?? opener?.textContent;
        const equivalent = controls.filter((control) =>
          key
            ? control.dataset.focusReturn === key
            : opener?.id
              ? control.id === opener.id
              : Boolean(name) &&
                control.tagName === opener?.tagName &&
                (control.getAttribute('aria-label') ?? control.textContent) === name &&
                control.getAttribute('href') === opener?.getAttribute('href')
        );
        if (equivalent.length === 1) equivalent[0].focus();
        else {
          const fallback = document.getElementById('portal-content');
          if (fallback && isVisible(fallback)) fallback.focus();
        }
      }
    };
  }, []);

  function containFocus(event: KeyboardEvent<HTMLDialogElement>) {
    if (event.key !== 'Tab') return;
    const controls = [
      ...event.currentTarget.querySelectorAll<HTMLElement>(focusableSelector),
    ].filter((element) => isEnabled(element) && isVisible(element));
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (!first) {
      event.preventDefault();
      heading.current?.focus();
    } else if (
      event.shiftKey &&
      (document.activeElement === first || document.activeElement === heading.current)
    ) {
      event.preventDefault();
      last.focus();
      last.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
      // Refocusing the sole control after responsive reflow does not scroll it.
      first.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
    } else if (
      document.activeElement !== heading.current &&
      !controls.includes(document.activeElement as HTMLElement)
    ) {
      event.preventDefault();
      const control = event.shiftKey ? last : first;
      control.focus();
      control.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
    }
  }

  const review = layout === 'review';
  const titleHeading = (
    <h2
      ref={heading}
      id={`${id}-title`}
      tabIndex={-1}
      className="text-xl font-semibold tracking-tight focus:outline-none"
    >
      {title}
    </h2>
  );
  const content = (
    <>
      <div
        id={`${id}-description`}
        className="break-words text-sm leading-relaxed text-muted-foreground"
      >
        {description}
      </div>
      {children}
    </>
  );

  return (
    <dialog
      ref={dialog}
      aria-labelledby={`${id}-title`}
      aria-describedby={`${id}-description`}
      data-testid={testId}
      data-layout={layout}
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
      onKeyDown={containFocus}
      className={cn(
        'border bg-background p-0 text-foreground shadow-xl backdrop:bg-black/60',
        review
          ? '!m-0 h-[100svh] max-h-[100svh] w-full max-w-none overflow-hidden rounded-none supports-[height:100dvh]:h-[100dvh] supports-[height:100dvh]:max-h-[100dvh] md:!m-auto md:h-auto md:max-h-[calc(100svh-2rem)] md:w-[calc(100%-2rem)] md:max-w-2xl md:rounded-xl md:supports-[height:100dvh]:h-auto md:supports-[height:100dvh]:max-h-[calc(100dvh-2rem)]'
          : 'm-auto max-h-[calc(100svh-2rem)] w-[calc(100%-2rem)] max-w-lg overflow-y-auto rounded-xl'
      )}
    >
      {review ? (
        <div className="flex h-full max-h-[inherit] min-h-0 flex-col md:h-auto">
          <header className="shrink-0 border-b pb-4 pt-[max(1rem,env(safe-area-inset-top))] pl-[max(1.25rem,env(safe-area-inset-left))] pr-[max(1.25rem,env(safe-area-inset-right))] md:pl-[max(1.75rem,env(safe-area-inset-left))] md:pr-[max(1.75rem,env(safe-area-inset-right))]">
            {titleHeading}
          </header>
          <div
            data-dialog-scroll
            className="min-h-0 flex-1 space-y-5 overflow-y-auto overscroll-contain py-5 pl-[max(1.25rem,env(safe-area-inset-left))] pr-[max(1.25rem,env(safe-area-inset-right))] md:pl-[max(1.75rem,env(safe-area-inset-left))] md:pr-[max(1.75rem,env(safe-area-inset-right))]"
          >
            {content}
          </div>
          <footer className="shrink-0 space-y-3 border-t pt-4 pb-[max(1rem,env(safe-area-inset-bottom))] pl-[max(1.25rem,env(safe-area-inset-left))] pr-[max(1.25rem,env(safe-area-inset-right))] md:pl-[max(1.75rem,env(safe-area-inset-left))] md:pr-[max(1.75rem,env(safe-area-inset-right))]">
            {footer}
          </footer>
        </div>
      ) : (
        <div className="space-y-5 p-5 sm:p-7">
          {titleHeading}
          {content}
        </div>
      )}
    </dialog>
  );
}

const focusableSelector = 'button, input, select, textarea, a[href], summary, [tabindex]';

function isEnabled(element: HTMLElement) {
  return element.tabIndex >= 0 && !element.matches(':disabled, [aria-disabled="true"]');
}

function isVisible(element: HTMLElement) {
  if (!element.isConnected || element.closest('[hidden], [inert]')) return false;
  for (let ancestor: HTMLElement | null = element; ancestor; ancestor = ancestor.parentElement) {
    const style = getComputedStyle(ancestor);
    if (style.display === 'none' || style.visibility === 'hidden' || style.visibility === 'collapse')
      return false;
    if (ancestor instanceof HTMLDialogElement && !ancestor.open) return false;
    if (ancestor instanceof HTMLDetailsElement && !ancestor.open) {
      if (!ancestor.querySelector(':scope > summary')?.contains(element)) return false;
    }
  }
  return [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0);
}
