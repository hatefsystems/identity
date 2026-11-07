import { getTranslations } from 'next-intl/server';
import { UsersView } from '../_components/users-view';

export async function generateMetadata() {
  const t = await getTranslations('admin');
  return { title: t('metadata.accounts') };
}

export default function UsersPage() {
  return <UsersView />;
}
