import { getTranslations } from 'next-intl/server';
import { AuthCard } from '../_components/auth-card';
import { AccountRecovery } from '../_components/account-recovery';

export async function generateMetadata() {
  const t = await getTranslations('auth.pages');
  return { title: t('reclaim.metadata'), robots: { index: false, follow: false } };
}

export default async function RecoverAccountPage() {
  const t = await getTranslations('auth');
  return (
    <AuthCard
      title={t('pages.reclaim.title')}
      description={t('pages.reclaim.description')}
      footer={t('pages.reclaim.footer')}
    >
      <AccountRecovery />
    </AuthCard>
  );
}
