'use client';

import { useTranslations } from 'next-intl';
import type { TranslationValues } from 'next-intl';
import type { Message, MessageKey } from './messages';

export function useMessage() {
  const t = useTranslations();
  // Code-to-descriptor maps carry heterogeneous keys in non-React modules.
  // Preserve key typing here; ICU argument parity is independently checked for
  // every leaf. Direct component translations retain literal argument inference.
  const translate = t as (key: MessageKey, values?: TranslationValues) => string;
  return (message: Message | undefined) => (message ? translate(message.key, message.values) : '');
}
