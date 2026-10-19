'use client';

import { Button } from '@hatef/ui';
import './global.css';

export default function GlobalError() {
  return (
    <html lang="en">
      <body className="min-h-screen bg-background font-sans text-foreground antialiased">
        <main className="container flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-16 text-center">
          <h1 className="text-3xl font-bold tracking-tight">Something went wrong</h1>
          <p className="max-w-md text-muted-foreground">
            The portal could not load. Please reload the page to try again.
          </p>
          <Button type="button" onClick={() => window.location.reload()}>
            Reload page
          </Button>
        </main>
      </body>
    </html>
  );
}
