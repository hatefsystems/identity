import { connection } from 'next/server';
import localFont from 'next/font/local';
import { getTranslations } from 'next-intl/server';
import { getDisplayPreferences } from '../i18n/server';
import { getMessagesForLocale } from '../i18n/messages';
import { DisplayProvider } from '../i18n/provider';
import { timeZones } from '../i18n/config';
import './global.css';

const persianFont = localFont({
  src: './fonts/Vazirmatn[wght].woff2',
  weight: '100 900',
  style: 'normal',
  display: 'swap',
  preload: false,
  fallback: ['Tahoma', 'Arial', 'sans-serif'],
  adjustFontFallback: 'Arial',
});

export async function generateMetadata() {
  const t = await getTranslations('metadata');
  return { title: t('title'), description: t('description') };
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Even static-content pages need fresh HTML matching the request's CSP nonce.
  await connection();
  const preferences = await getDisplayPreferences();

  return (
    <html lang={preferences.locale} dir={preferences.locale === 'fa-IR' ? 'rtl' : 'ltr'} suppressHydrationWarning>
      <body className={`min-h-screen bg-background text-foreground antialiased ${preferences.locale === 'fa-IR' ? persianFont.className : 'font-sans'}`}>
        <DisplayProvider preferences={preferences} messages={getMessagesForLocale(preferences.locale)} timeZones={timeZones}>
          {children}
        </DisplayProvider>
      </body>
    </html>
  );
}
