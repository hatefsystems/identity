import type { TranslationValues } from 'next-intl';
import en from '../messages/en';
import fa from '../messages/fa-IR';
import type { Locale } from './config';
import type { CatalogShape, LocalizedCatalog, MessageKeys } from './types';

export type Messages = LocalizedCatalog<typeof en, typeof fa>;
export type MessageKey = MessageKeys<typeof en>;
export type MessageDescriptor = { key: MessageKey; values?: TranslationValues };
export type Message = MessageDescriptor | '';

type MessageTree = { [key: string]: string | MessageTree };

// Only keys present in the trusted English catalog can enter the rendered catalog.
export function mergeMessages<T extends MessageTree>(base: T, candidate: unknown): CatalogShape<T> {
  const source =
    candidate && typeof candidate === 'object' && !Array.isArray(candidate)
      ? (candidate as Record<string, unknown>)
      : {};
  const result: MessageTree = {};
  for (const [key, value] of Object.entries(base)) {
    result[key] =
      typeof value === 'string'
        ? typeof source[key] === 'string'
          ? source[key]
          : value
        : mergeMessages(value, source[key]);
  }
  return result as CatalogShape<T>;
}

export function getMessagesForLocale(locale: Locale): Messages {
  // The candidate is a statically imported, shape-checked catalog. The generic
  // merger also accepts unknown values for fallback testing; only this trusted
  // boundary may narrow its leaves to the two committed literal catalogs.
  return mergeMessages(en, locale === 'fa-IR' ? fa : en) as Messages;
}
