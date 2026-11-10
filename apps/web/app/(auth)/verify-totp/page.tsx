import { getTranslations } from 'next-intl/server';
import { AuthCard, AuthLink } from '../_components/auth-card';
import { TotpScreen } from '../_components/screens';

export async function generateMetadata() {
  const t = await getTranslations('auth.pages');
  return { title: t('totp.metadata') };
}

export default async function TotpPage() {
  const t = await getTranslations('auth');
  return (
    <AuthCard
      title={t('pages.totp.title')}
      description={t('pages.totp.description')}
      footer={<AuthLink href="/register">{t('home.register')}</AuthLink>}
    >
      <TotpScreen />
    </AuthCard>
  );
}
