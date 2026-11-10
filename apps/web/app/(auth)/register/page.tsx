import { getTranslations } from 'next-intl/server';
import { RegistrationScreen } from '../_components/screens';

export async function generateMetadata() {
  const t = await getTranslations('auth.pages');
  return { title: t('register.metadata') };
}

export default async function RegistrationPage() {
  return <RegistrationScreen />;
}
