import { getTranslations } from 'next-intl/server';
import { SecurityView } from '../_components/security-view';

export async function generateMetadata() {
  const t = await getTranslations('portal.metadata');
  return { title: t('security') };
}
export default function SecurityPage() {
  return <SecurityView />;
}
