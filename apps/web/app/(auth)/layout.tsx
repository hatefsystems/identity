import { getTranslations } from 'next-intl/server';
import { PreferenceControls } from '../../i18n/preferences';
import { BrandLink } from '../_components/brand-link';
import type { ReactNode } from 'react';

export default async function AuthLayout({ children }: { children: ReactNode }) {
  const t = await getTranslations('auth');
  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted/30 px-4 py-8 sm:px-6 sm:py-12">
      <header>
        <BrandLink homeLabel={t('homeLabel')}>{t('brand')}</BrandLink>
      </header>
      <div className="w-full max-w-md">
        <PreferenceControls />
      </div>
      <main className="w-full max-w-md min-w-0">{children}</main>
      <p className="max-w-md text-center text-xs leading-relaxed text-muted-foreground">
        {t('tagline')}
      </p>
    </div>
  );
}
