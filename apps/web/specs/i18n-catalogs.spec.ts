/** @jest-environment node */

import { parse, TYPE, type MessageFormatElement } from '@formatjs/icu-messageformat-parser';
import { createTranslator, type RichTranslationValues } from 'next-intl';
import en from '../messages/en';
import fa from '../messages/fa-IR';
import { getMessagesForLocale, mergeMessages } from '../i18n/messages';

function leaves(value: object, prefix = ''): Record<string, string> {
  return Object.fromEntries(
    Object.entries(value).flatMap(([key, entry]) => {
      const path = prefix ? `${prefix}.${key}` : key;
      return typeof entry === 'string' ? [[path, entry]] : Object.entries(leaves(entry, path));
    })
  );
}

function argumentsOf(
  elements: MessageFormatElement[],
  values: RichTranslationValues = {},
  signature = new Set<string>()
) {
  for (const element of elements) {
    if (element.type === TYPE.literal || element.type === TYPE.pound) continue;
    signature.add(`${element.type}:${element.value}`);
    if (element.type === TYPE.tag) {
      values[element.value] = (chunks) => chunks;
      argumentsOf(element.children, values, signature);
    } else if (element.type === TYPE.plural || element.type === TYPE.select) {
      values[element.value] = element.type === TYPE.plural ? 2 : Object.keys(element.options)[0];
      for (const option of Object.values(element.options))
        argumentsOf(option.value, values, signature);
    } else if (element.type === TYPE.date || element.type === TYPE.time) {
      values[element.value] = new Date('2024-03-20T12:00:00Z');
    } else {
      values[element.value] = element.type === TYPE.number ? 2 : 'sample';
    }
  }
  return { values, signature: [...signature].sort() };
}

describe('complete and compatible committed translation catalogs', () => {
  const english = leaves(en);
  const persian = leaves(fa);

  it('requires exact Persian leaf parity and nonempty strings', () => {
    expect(Object.keys(persian).sort()).toEqual(Object.keys(english).sort());
    for (const [key, text] of Object.entries(persian)) {
      expect({ key, nonempty: text.trim().length > 0 }).toEqual({ key, nonempty: true });
    }
  });

  it('parses and formats every message with compatible ICU arguments and rich slots', () => {
    for (const [key, englishText] of Object.entries(english)) {
      const expected = argumentsOf(parse(englishText));
      expect({ key, arguments: argumentsOf(parse(persian[key])).signature }).toEqual({
        key,
        arguments: expected.signature,
      });
      for (const locale of ['en', 'fa-IR'] as const) {
        const translator = createTranslator({
          locale,
          timeZone: 'UTC',
          messages: { entry: locale === 'en' ? englishText : persian[key] },
          onError: (error) => {
            throw new Error(`${locale}/${key}: ${error.code}`);
          },
        });
        expect(translator.rich('entry', expected.values)).toBeDefined();
      }
    }
  });

  it('merges an intentionally missing Persian leaf from English without accepting extra keys', () => {
    const base = { section: { first: 'First', second: 'Second' } } as const;
    expect(
      mergeMessages(base, { section: { first: 'نخست', extra: 'untrusted' }, extra: 'untrusted' })
    ).toEqual({ section: { first: 'نخست', second: 'Second' } });
    expect(mergeMessages(base, { section: null })).toEqual(base);
    expect(mergeMessages(base, { section: { first: 42, second: {} } })).toEqual(base);
  });

  it('does not share mutable catalog trees between requests', () => {
    const first = getMessagesForLocale('fa-IR');
    // Mutation is deliberate: each caller must receive its own fallback tree.
    (first.common as { pageError: string }).pageError = 'changed';
    expect(getMessagesForLocale('fa-IR').common.pageError).toBe(fa.common.pageError);
    expect(getMessagesForLocale('en').common.pageError).toBe(en.common.pageError);
  });

  it('supplies the fixed legal wire value at rendering instead of serializing it in public catalogs', () => {
    const kind = 'preservation_request';
    for (const locale of ['en', 'fa-IR'] as const) {
      const messages = getMessagesForLocale(locale);
      expect(JSON.stringify(messages)).not.toContain(kind);
      const translator = createTranslator({ locale, messages });
      expect(translator.rich('legal.values.serverFixed', {
        kind, value: (chunks) => chunks,
      })).toContain(kind);
    }
  });
});
