import { getTranslations } from 'next-intl/server';
import { AuthCard, AuthLink } from '../_components/auth-card';
import { ResetPasswordScreen } from '../_components/screens';

export async function generateMetadata() {
  const t = await getTranslations('auth.pages');
  return { title: t('reset.metadata') };
}

export default async function ResetPasswordPage() {
  const t = await getTranslations('auth');
  return (
    <AuthCard
      title={t('pages.reset.title')}
      description={t('pages.reset.description')}
      footer={<AuthLink href="/register">{t('home.register')}</AuthLink>}
    >
      <ResetPasswordScreen />
    </AuthCard>
  );
}
