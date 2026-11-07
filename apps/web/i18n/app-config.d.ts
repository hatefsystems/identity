import en from '../messages/en';
import fa from '../messages/fa-IR';
import type { LocalizedCatalog } from './types';
import type { Locale } from './config';
import type { formats } from './formats';

declare module 'next-intl' {
  interface AppConfig {
    Locale: Locale;
    Messages: LocalizedCatalog<typeof en, typeof fa>;
    Formats: typeof formats;
  }
}
