import type { ReactNode } from 'react';
import { PortalProvider } from '../_components/portal-provider';

export const metadata = {
  title: { default: 'Admin control panel | Hatef Identity', template: '%s | Hatef Identity' },
  robots: { index: false, follow: false },
};

export default function AdminLayout({ children }: { children: ReactNode }) {
  // Cookie presence alone never renders privileged data or forms.
  return <PortalProvider surface="admin">{children}</PortalProvider>;
}
