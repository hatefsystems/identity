import { getTranslations } from 'next-intl/server';
import { IntegrityView } from '../_components/integrity-view';

export async function generateMetadata() {
  const t = await getTranslations('integrity');
  return { title: t('metadata') };
}
export default function IntegrityPage() {
  return <IntegrityView />;
}
