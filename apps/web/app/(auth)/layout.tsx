import { ShieldCheck } from 'lucide-react';
import Link from 'next/link';
import type { ReactNode } from 'react';

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted/30 px-4 py-8 sm:px-6 sm:py-12">
      <header>
        <Link
          href="/"
          className="flex min-h-11 items-center gap-3 rounded-md px-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
          aria-label="Hatef Identity home"
        >
          <span className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheck aria-hidden="true" className="size-5" />
          </span>
          <span className="text-base font-semibold tracking-tight">
            Hatef <span className="font-normal text-muted-foreground">Identity</span>
          </span>
        </Link>
      </header>
      <main className="w-full max-w-md min-w-0">{children}</main>
      <p className="max-w-md text-center text-xs leading-relaxed text-muted-foreground">
        One identity for the Hatef ecosystem.
      </p>
    </div>
  );
}
