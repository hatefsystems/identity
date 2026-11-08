import { getTranslations } from 'next-intl/server';
import { AuthCard, AuthLink } from '../_components/auth-card';
import { RegistrationScreen } from '../_components/screens';

export async function generateMetadata() {
  const t = await getTranslations('auth.pages');
  return { title: t('register.metadata') };
}

export default async function RegistrationPage() {
  const t = await getTranslations('auth');
  return (
    <AuthCard
      title={t('pages.register.title')}
      description={t('pages.register.description')}
      footer={
        <>
          <span>{t('pages.register.existing')}</span>
          <AuthLink href="/login">{t('home.signIn')}</AuthLink>
        </>
      }
    >
      <RegistrationScreen />
    </AuthCard>
  );
}
