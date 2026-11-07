import { getTranslations } from 'next-intl/server';
import { AuditView } from '../_components/audit-view';

export async function generateMetadata() {
  const t = await getTranslations('audit');
  return { title: t('metadata') };
}
export default function AuditLogsPage() {
  return <AuditView />;
}
