import { getTranslations } from 'next-intl/server';
import { AuthCard, AuthLink } from '../_components/auth-card';
import { LoginScreen } from '../_components/screens';

export async function generateMetadata() {
  const t = await getTranslations('auth.pages');
  return { title: t('login.metadata') };
}

export default async function LoginPage() {
  const t = await getTranslations('auth');
  return (
    <AuthCard
      title={t('pages.login.title')}
      description={t('pages.login.description')}
      footer={
        <>
          <span>{t('pages.login.new')}</span>
          <AuthLink href="/register">{t('home.register')}</AuthLink>
        </>
      }
    >
      <LoginScreen />
    </AuthCard>
  );
}
