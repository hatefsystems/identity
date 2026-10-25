import type { ReactNode } from 'react';
import { PortalProvider } from './_components/portal-provider';

export const metadata = {
  title: { default: 'Your account | Hatef Identity', template: '%s | Hatef Identity' },
  robots: { index: false, follow: false },
};

export default function DashboardLayout({ children }: { children: ReactNode }) {
  // The server renders only the shell. Cookie presence is not authorization;
  // personal content requires the browser's DPoP-authenticated Go bootstrap.
  return <PortalProvider>{children}</PortalProvider>;
}
