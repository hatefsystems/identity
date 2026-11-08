import { getTranslations } from 'next-intl/server';
import { PrivacyView } from '../_components/privacy-view';

export async function generateMetadata() {
  const t = await getTranslations('portal.metadata');
  return { title: t('privacy') };
}

export default function PrivacyPage() {
  return <PrivacyView />;
}
