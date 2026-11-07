import { getTranslations } from 'next-intl/server';
import { LegalView } from '../_components/legal-view';

export async function generateMetadata() {
  const t = await getTranslations('legal');
  return { title: t('title') };
}

export default function LegalPage() {
  return <LegalView />;
}
