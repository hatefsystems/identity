'use client';

import { Button } from '@hatef/ui';
import { commonEn, commonFa } from '../messages/common';
import './global.css';

export default function GlobalError() {
  return (
    <html lang="en" dir="ltr">
      <body className="min-h-screen bg-background font-sans text-foreground antialiased">
        <main className="container flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-16 text-center">
          <section lang="en" dir="ltr" className="space-y-6">
            <h1 className="text-3xl font-bold tracking-tight">{commonEn.pageError}</h1>
            <p className="max-w-md text-muted-foreground">{commonEn.fatalDescription}</p>
            <Button type="button" onClick={() => window.location.reload()}>{commonEn.reloadPage}</Button>
          </section>
          <section lang="fa-IR" dir="rtl" className="space-y-6 leading-relaxed">
            <h2 className="text-3xl font-bold">{commonFa.pageError}</h2>
            <p className="max-w-md text-muted-foreground">{commonFa.fatalDescription}</p>
            <Button type="button" onClick={() => window.location.reload()}>{commonFa.reloadPage}</Button>
          </section>
        </main>
      </body>
    </html>
  );
}
