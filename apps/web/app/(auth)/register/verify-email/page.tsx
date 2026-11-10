import { getTranslations } from 'next-intl/server';
import { RegistrationEmailVerification } from '../../../_components/registration';

export async function generateMetadata() {
  const t = await getTranslations('registration');
  return { title: t('verifyMetadata'), referrer: 'no-referrer' as const };
}

export default async function VerifyRegistrationEmailPage() {
  return <RegistrationEmailVerification />;
}
