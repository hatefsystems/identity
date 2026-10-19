import { connection } from 'next/server';
import './global.css';

export const metadata = {
  title: 'Hatef Identity Platform',
  description:
    'Centralized, privacy-first Identity Provider (IdP) and unified access portal for the Hatef ecosystem.',
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Even static-content pages need fresh HTML matching the request's CSP nonce.
  await connection();

  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background font-sans text-foreground antialiased">
        {children}
      </body>
    </html>
  );
}
