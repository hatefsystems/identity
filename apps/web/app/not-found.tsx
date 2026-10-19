import Link from 'next/link';
import { Button } from '@hatef/ui';

export default function NotFound() {
  return (
    <main className="container flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-16 text-center">
      <p className="text-sm font-medium text-muted-foreground">404</p>
      <h1 className="text-3xl font-bold tracking-tight">Page not found</h1>
      <p className="max-w-md text-muted-foreground">The page you requested could not be found.</p>
      <Button asChild>
        <Link href="/">Return home</Link>
      </Button>
    </main>
  );
}
