import './global.css';

export const metadata = {
  title: 'Hatef Identity Platform',
  description:
    'Centralized, privacy-first Identity Provider (IdP) and unified access portal for the Hatef ecosystem.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background font-sans text-foreground antialiased">
        {children}
      </body>
    </html>
  );
}
