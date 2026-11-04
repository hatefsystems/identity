import { getTranslations } from 'next-intl/server';
import { Overview } from './_components/overview';

export async function generateMetadata() {
  const t = await getTranslations('portal.metadata');
  return { title: t('overview') };
}
export default function DashboardPage() {
  return <Overview />;
}
