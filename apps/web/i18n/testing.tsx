import type { ReactElement, ReactNode } from 'react';
import { createTranslator } from 'next-intl';
import { render as testingRender, type RenderOptions } from '@testing-library/react';
import { defaultPreferences, type DisplayPreferences, type Locale } from './config';
import { getMessagesForLocale, type Messages } from './messages';
import { DisplayProvider } from './provider';

export * from '@testing-library/react';

export function I18nTestProvider({
  children,
  locale,
  preferences,
}: {
  children: ReactNode;
  locale?: Locale;
  preferences?: Partial<DisplayPreferences>;
}) {
  const resolved = { ...defaultPreferences, ...preferences, ...(locale ? { locale } : {}) };
  return (
    <DisplayProvider preferences={resolved} messages={getMessagesForLocale(resolved.locale)}>
      {children}
    </DisplayProvider>
  );
}

export function render(
  ui: ReactElement,
  options: RenderOptions & {
    locale?: Locale;
    preferences?: Partial<DisplayPreferences>;
  } = {}
) {
  const { locale, preferences, wrapper: Wrapper, ...rest } = options;
  return testingRender(ui, {
    ...rest,
    wrapper: ({ children }) => (
      <I18nTestProvider locale={locale} preferences={preferences}>
        {Wrapper ? <Wrapper>{children}</Wrapper> : children}
      </I18nTestProvider>
    ),
  });
}

export async function getTestTranslations<Namespace extends keyof Messages>(
  namespace: Namespace,
  locale: Locale = 'en'
) {
  return createTranslator({ locale, messages: getMessagesForLocale(locale), namespace });
}
