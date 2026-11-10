import type { CatalogShape } from '../i18n/types';

export const preferencesEn = {
  label: 'Language and display preferences',
  language: 'Language',
  english: 'English',
  persian: 'فارسی',
  displaySettings: 'Display settings',
  appearance: 'Appearance',
  system: 'System',
  light: 'Light',
  dark: 'Dark',
  calendar: 'Calendar',
  automatic: 'Language default',
  gregorian: 'Gregorian',
  jalali: 'Jalali (Persian)',
  timeZone: 'Time zone',
  deviceTimeZone: 'Use device time zone',
  displayOnly:
    'Appearance, calendar and time zone change presentation only, not deadlines or stored information.',
  saving: 'Saving preferences…',
  saved: 'Preferences saved.',
  failed: 'Preferences could not be saved. Your previous settings are unchanged.',
  unsupportedZone: 'Your device time zone is not supported. Select a time zone from the list.',
} as const;

export const preferencesFa = {
  label: 'تنظیمات زبان و نمایش',
  language: 'زبان',
  english: 'English',
  persian: 'فارسی',
  displaySettings: 'تنظیمات نمایش',
  appearance: 'ظاهر',
  system: 'سیستم',
  light: 'روشن',
  dark: 'تیره',
  calendar: 'تقویم',
  automatic: 'پیش‌فرض زبان',
  gregorian: 'میلادی',
  jalali: 'هجری خورشیدی (جلالی)',
  timeZone: 'منطقهٔ زمانی',
  deviceTimeZone: 'استفاده از منطقهٔ زمانی دستگاه',
  displayOnly:
    'ظاهر، تقویم و منطقهٔ زمانی فقط شیوهٔ نمایش را تغییر می‌دهند؛ مهلت‌ها و اطلاعات ذخیره‌شده تغییر نمی‌کنند.',
  saving: 'در حال ذخیرهٔ تنظیمات…',
  saved: 'تنظیمات ذخیره شد.',
  failed: 'ذخیرهٔ تنظیمات ممکن نشد. تنظیمات قبلی شما تغییر نکرده است.',
  unsupportedZone:
    'منطقهٔ زمانی دستگاه شما پشتیبانی نمی‌شود. یک منطقهٔ زمانی از فهرست انتخاب کنید.',
} as const satisfies CatalogShape<typeof preferencesEn>;
