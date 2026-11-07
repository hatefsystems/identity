import { getTranslations } from 'next-intl/server';
import { AuthCard, AuthLink } from '../../_components/auth-card';
import { PasskeyScreen } from '../../_components/screens';

export async function generateMetadata() {
  const t = await getTranslations('auth.pages');
  return { title: t('passkey.metadata') };
}

export default async function PasskeyPage() {
  const t = await getTranslations('auth');
  return (
    <AuthCard
      title={t('pages.passkey.title')}
      description={t('pages.passkey.description')}
      footer={<AuthLink href="/login">{t('pages.returnSignIn')}</AuthLink>}
    >
      <PasskeyScreen />
    </AuthCard>
  );
}
