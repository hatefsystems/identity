'use client';

import { Button } from '@hatef/ui';

export default function ErrorPage({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="container flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-16 text-center">
      <h1 className="text-3xl font-bold tracking-tight">Something went wrong</h1>
      <p className="max-w-md text-muted-foreground">
        We could not display this page. Please try again.
      </p>
      <Button type="button" onClick={reset}>
        Try again
      </Button>
    </main>
  );
}
