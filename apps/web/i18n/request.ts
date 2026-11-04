import { getRequestConfig } from 'next-intl/server';
import { getMessagesForLocale } from './messages';
import { formats } from './formats';
import { getDisplayPreferences } from './server';
import { commonEn, commonFa } from '../messages/common';

export default getRequestConfig(async () => {
  const preferences = await getDisplayPreferences();
  return {
    locale: preferences.locale,
    timeZone: preferences.timeZone,
    messages: getMessagesForLocale(preferences.locale),
    formats,
    onError(error) {
      // Never log interpolation values or the original exception message.
      console.warn('i18n', error.code);
    },
    getMessageFallback() {
      return (preferences.locale === 'fa-IR' ? commonFa : commonEn).unavailable;
    },
  };
});
