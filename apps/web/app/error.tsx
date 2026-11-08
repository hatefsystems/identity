'use client';

import { Button } from '@hatef/ui';
import { useTranslations } from 'next-intl';

export default function ErrorPage({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const t = useTranslations('common');
  return (
    <main className="container flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-16 text-center">
      <h1 className="text-3xl font-bold tracking-tight">{t('pageError')}</h1>
      <p className="max-w-md text-muted-foreground">
        {t('pageErrorDescription')}
      </p>
      <Button type="button" onClick={reset}>
        {t('tryAgain')}
      </Button>
    </main>
  );
}
