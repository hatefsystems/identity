'use client';

import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from 'react';

export function NativeDialog({
  title,
  description,
  children,
  onCancel,
  testId,
}: {
  title: string;
  description: ReactNode;
  children: ReactNode;
  onCancel: () => void;
  testId?: string;
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
      if (opener?.isConnected) opener.focus();
      else document.getElementById('portal-content')?.focus();
    };
  }, []);

  function containFocus(event: KeyboardEvent<HTMLDialogElement>) {
    if (event.key !== 'Tab') return;
    const controls = [
      ...event.currentTarget.querySelectorAll<HTMLElement>(
        'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]'
      ),
    ].filter((element) => !element.closest('[hidden]'));
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
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <dialog
      ref={dialog}
      aria-labelledby={`${id}-title`}
      aria-describedby={`${id}-description`}
      data-testid={testId}
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
      onKeyDown={containFocus}
      className="m-auto max-h-[calc(100svh-2rem)] w-[calc(100%-2rem)] max-w-lg overflow-y-auto rounded-xl border bg-background p-0 text-foreground shadow-xl backdrop:bg-black/60"
    >
      <div className="space-y-5 p-5 sm:p-7">
        <h2
          ref={heading}
          id={`${id}-title`}
          tabIndex={-1}
          className="text-xl font-semibold tracking-tight focus:outline-none"
        >
          {title}
        </h2>
        <div
          id={`${id}-description`}
          className="break-words text-sm leading-relaxed text-muted-foreground"
        >
          {description}
        </div>
        {children}
      </div>
    </dialog>
  );
}
