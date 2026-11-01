import { cn } from '@hatef/ui';
import type { ReactNode } from 'react';

export function PageHeading({ title, children }: { title: string; children: ReactNode }) {
  return (
    <header className="space-y-2 border-b pb-6">
      <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h1>
      <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground">{children}</p>
    </header>
  );
}

export function Panel({
  title,
  children,
  id,
}: {
  title: string;
  children: ReactNode;
  id?: string;
}) {
  return (
    <section
      aria-labelledby={id}
      className="min-w-0 space-y-5 rounded-xl border bg-card p-5 text-card-foreground sm:p-6"
    >
      <h2 id={id} className="text-lg font-semibold tracking-tight">
        {title}
      </h2>
      {children}
    </section>
  );
}

export function Feedback({ error = '', status = '' }: { error?: string; status?: string }) {
  return (
    <>
      <p
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className={status ? 'text-sm leading-relaxed text-muted-foreground' : 'sr-only'}
      >
        {status}
      </p>
      {error && (
        <p
          role="alert"
          className="rounded-md border border-red-700 bg-red-50 p-3 text-sm leading-relaxed text-red-800 dark:border-red-400 dark:bg-red-950 dark:text-red-200"
        >
          {error}
        </p>
      )}
    </>
  );
}

export const controlClass = 'h-auto min-h-11 whitespace-normal';
export const inputClass = 'h-11 min-w-0 border-slate-500 dark:border-slate-400';
export const linkClass =
  'inline-flex min-h-11 items-center rounded-md px-2 text-sm font-medium underline decoration-border underline-offset-4 hover:decoration-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2';

export function DateLabel({ value, className }: { value: string; className?: string }) {
  return (
    <time dateTime={value} className={cn('break-words', className)}>
      {new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
    </time>
  );
}
