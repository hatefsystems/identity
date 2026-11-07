import { getTranslations } from 'next-intl/server';
import type { ReactNode } from 'react';
import { PortalProvider } from '../_components/portal-provider';

export async function generateMetadata() {
  const t = await getTranslations('admin.metadata');
  return {
    title: { default: t('title'), template: t('template') },
    robots: { index: false, follow: false },
  };
}

export default function AdminLayout({ children }: { children: ReactNode }) {
  // Cookie presence alone never renders privileged data or forms.
  return <PortalProvider surface="admin">{children}</PortalProvider>;
}
