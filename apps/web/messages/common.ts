import type { CatalogShape } from '../i18n/types';

export const commonEn = {
  unavailable: 'This text is unavailable.',
  pageError: 'Something went wrong',
  pageErrorDescription: 'We could not display this page. Please try again.',
  tryAgain: 'Try again',
  notFound: 'Page not found',
  notFoundDescription: 'The page you requested could not be found.',
  returnHome: 'Return home',
  fatalDescription: 'The portal could not load. Please reload the page to try again.',
  reloadPage: 'Reload page',
} as const;

export const commonFa = {
  unavailable: 'این متن در دسترس نیست.',
  pageError: 'مشکلی پیش آمد',
  pageErrorDescription: 'نمایش این صفحه ممکن نشد. دوباره تلاش کنید.',
  tryAgain: 'تلاش دوباره',
  notFound: 'صفحه پیدا نشد',
  notFoundDescription: 'صفحه‌ای که درخواست کرده‌اید پیدا نشد.',
  returnHome: 'بازگشت به صفحهٔ اصلی',
  fatalDescription: 'بارگذاری درگاه ممکن نشد. برای تلاش دوباره، صفحه را بازخوانی کنید.',
  reloadPage: 'بازخوانی صفحه',
} as const satisfies CatalogShape<typeof commonEn>;
