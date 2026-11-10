import Link from 'next/link';
import { ShieldCheck } from 'lucide-react';
import type { MouseEventHandler, ReactNode } from 'react';

export function BrandLink({ children, homeLabel, onClick }: {
  children: ReactNode;
  homeLabel: string;
  onClick?: MouseEventHandler<HTMLAnchorElement>;
}) {
  return (
    <Link
      href="/"
      prefetch={false}
      onClick={onClick}
      aria-label={homeLabel}
      className="flex min-h-11 items-center gap-3 rounded-md px-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
    >
      <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
        <ShieldCheck aria-hidden="true" className="size-5" />
      </span>
      <bdi dir="auto" className="text-base font-semibold tracking-tight">{children}</bdi>
    </Link>
  );
}
