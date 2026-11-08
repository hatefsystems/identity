import { getTranslations } from 'next-intl/server';
import type { ReactNode } from 'react';
import { PortalProvider } from './_components/portal-provider';

export async function generateMetadata() {
  const t = await getTranslations('portal.metadata');
  const metadata = await getTranslations('auth');
  return {
    title: {
      default: `${t('title')} | ${metadata('brand')}`,
      template: `%s | ${metadata('brand')}`,
    },
    robots: { index: false, follow: false },
  };
}

export default function DashboardLayout({ children }: { children: ReactNode }) {
  // The server renders only the shell. Cookie presence is not authorization;
  // personal content requires the browser's DPoP-authenticated Go bootstrap.
  return <PortalProvider>{children}</PortalProvider>;
}
