import { getTranslations } from 'next-intl/server';
import { AuthCard, AuthLink } from '../_components/auth-card';
import { LoginScreen } from '../_components/screens';

export async function generateMetadata() {
  const t = await getTranslations('auth.pages');
  return { title: t('login.metadata') };
}

export default async function LoginPage() {
  const t = await getTranslations('auth');
  const loginEnabled = process.env.NEXT_PUBLIC_LOGIN_ENABLED === 'true';
  return (
    <AuthCard
      title={t('pages.login.title')}
      description={t(loginEnabled ? 'login.description' : 'pages.login.description')}
      footer={
        <>
          <span>{t('pages.login.new')}</span>
          <AuthLink href="/register">{t('home.register')}</AuthLink>
        </>
      }
    >
      <LoginScreen enabled={loginEnabled} />
    </AuthCard>
  );
}
