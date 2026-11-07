import type { CatalogShape } from '../i18n/types';

export const metadataEn = {
  title: 'Hatef Identity Platform',
  description:
    'Centralized, privacy-first Identity Provider (IdP) and unified access portal for the Hatef ecosystem.',
} as const;

export const metadataFa = {
  title: 'سامانهٔ هویت هاتف',
  description:
    'ارائه‌دهندهٔ متمرکز هویت با اولویت حریم خصوصی و درگاه یکپارچهٔ دسترسی به زیست‌بوم هاتف.',
} as const satisfies CatalogShape<typeof metadataEn>;
