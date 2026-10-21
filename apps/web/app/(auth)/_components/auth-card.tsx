import { Card, CardContent, CardDescription, CardFooter, CardHeader } from '@hatef/ui';
import type { ReactNode } from 'react';
import Link from 'next/link';

export function AuthLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link
      href={href}
      className="inline-flex min-h-11 items-center justify-center rounded-sm px-1 text-sm font-medium text-foreground underline decoration-border underline-offset-4 hover:decoration-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
    >
      {children}
    </Link>
  );
}

export function AuthCard({
  title,
  description,
  children,
  footer,
}: {
  title: string;
  description: string;
  children: ReactNode;
  footer: ReactNode;
}) {
  return (
    <Card className="w-full min-w-0">
      <CardHeader className="space-y-3 p-6 sm:p-8">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <CardDescription className="leading-relaxed">{description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5 px-6 pb-6 sm:px-8 sm:pb-8">{children}</CardContent>
      <CardFooter className="flex-wrap justify-center gap-x-1 border-t bg-muted/30 px-4 py-3 text-center text-sm text-muted-foreground">
        {footer}
      </CardFooter>
    </Card>
  );
}
