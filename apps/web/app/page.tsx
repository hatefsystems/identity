import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle } from '@hatef/ui';
import Link from 'next/link';
import { getTranslations } from 'next-intl/server';
import { PreferenceControls } from '../i18n/preferences';

export default async function Index() {
  const t = await getTranslations('auth.home');
  return (
    <main className="container flex min-h-screen flex-col items-center justify-center gap-8 py-16">
      <div className="flex flex-col items-center gap-2 text-center">
        <h1 className="text-4xl font-bold tracking-tight">{t('title')}</h1>
        <p className="max-w-xl text-muted-foreground">{t('description')}</p>
      </div>

      <PreferenceControls />
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>{t('welcome')}</CardTitle>
          <CardDescription>{t('welcomeDescription')}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Button asChild className="h-11 w-full">
            <Link href="/login">{t('signIn')}</Link>
          </Button>
          <Button asChild variant="outline" className="h-11 w-full">
            <Link href="/register">{t('register')}</Link>
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
