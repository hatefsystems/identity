import Link from 'next/link';
import { Button } from '@hatef/ui';
import { getTranslations } from 'next-intl/server';

export default async function NotFound() {
  const t = await getTranslations('common');
  return (
    <main className="container flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-16 text-center">
      <p dir="ltr" className="text-sm font-medium text-muted-foreground">404</p>
      <h1 className="text-3xl font-bold tracking-tight">{t('notFound')}</h1>
      <p className="max-w-md text-muted-foreground">{t('notFoundDescription')}</p>
      <Button asChild>
        <Link href="/">{t('returnHome')}</Link>
      </Button>
    </main>
  );
}
