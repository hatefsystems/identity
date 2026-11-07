import { getTranslations } from 'next-intl/server';
import { SessionsView } from '../_components/sessions-view';

export async function generateMetadata() {
  const t = await getTranslations('portal.metadata');
  return { title: t('sessions') };
}
export default function SessionsPage() {
  return <SessionsView />;
}
