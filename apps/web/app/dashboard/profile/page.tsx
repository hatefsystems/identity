import { getTranslations } from 'next-intl/server';
import { ProfileEditor } from '../_components/profile-editor';

export async function generateMetadata() {
  const t = await getTranslations('portal.metadata');
  return { title: t('profile') };
}
export default function ProfilePage() {
  return <ProfileEditor />;
}
