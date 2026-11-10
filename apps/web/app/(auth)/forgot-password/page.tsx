import { getTranslations } from 'next-intl/server';
import { AuthCard, AuthLink } from '../_components/auth-card';
import { ForgotPasswordScreen } from '../_components/screens';

export async function generateMetadata() {
  const t = await getTranslations('auth.pages');
  return { title: t('forgot.metadata') };
}

export default async function ForgotPasswordPage() {
  const t = await getTranslations('auth');
  return (
    <AuthCard
      title={t('pages.forgot.title')}
      description={t('pages.forgot.description')}
      footer={<AuthLink href="/register">{t('home.register')}</AuthLink>}
    >
      <ForgotPasswordScreen />
    </AuthCard>
  );
}
