import { getTranslations } from 'next-intl/server';
import { RegistrationEmailVerification } from '../../../_components/registration';
import { AuthCard, AuthLink } from '../../_components/auth-card';

export async function generateMetadata() {
  const t = await getTranslations('registration');
  return { title: t('verifyMetadata'), referrer: 'no-referrer' as const };
}

export default async function VerifyRegistrationEmailPage() {
  const t = await getTranslations('registration');
  return (
    <AuthCard
      title={t('verifyTitle')}
      description={t('verifyDescription')}
      footer={<AuthLink href="/register">{t('restartLink')}</AuthLink>}
    >
      <RegistrationEmailVerification />
    </AuthCard>
  );
}
