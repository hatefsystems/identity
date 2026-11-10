'use client';

import { createContext, useContext, useLayoutEffect, type ReactNode } from 'react';
import { NextIntlClientProvider } from 'next-intl';
import { timeZones as defaultTimeZones, type DisplayPreferences, type ThemePreference } from './config';
import type { Messages } from './messages';
import { formats } from './formats';
import { commonEn, commonFa } from '../messages/common';

const DisplayContext = createContext<DisplayPreferences | undefined>(undefined);
const TimeZonesContext = createContext<readonly string[]>(defaultTimeZones);

function AppearanceController({ theme }: { theme: ThemePreference }) {
  useLayoutEffect(() => {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
    if (theme !== 'system') {
      root.classList.toggle('dark', theme === 'dark');
      return undefined;
    }
    try {
      const query = window.matchMedia('(prefers-color-scheme: dark)');
      const apply = () => root.classList.toggle('dark', query.matches === true);
      apply();
      query.addEventListener('change', apply);
      return () => query.removeEventListener('change', apply);
    } catch {
      root.classList.remove('dark');
    }
    return undefined;
  }, [theme]);
  return null;
}

export function DisplayProvider({
  children,
  preferences,
  messages,
  timeZones = defaultTimeZones,
}: {
  children: ReactNode;
  preferences: DisplayPreferences;
  messages: Messages;
  timeZones?: readonly string[];
}) {
  return (
    <DisplayContext.Provider value={preferences}>
      <AppearanceController theme={preferences.theme} />
      <TimeZonesContext.Provider value={timeZones}>
        <NextIntlClientProvider
          locale={preferences.locale}
          timeZone={preferences.timeZone}
          messages={messages}
          formats={formats}
          onError={(error) => console.warn('i18n', error.code)}
          getMessageFallback={() =>
            (preferences.locale === 'fa-IR' ? commonFa : commonEn).unavailable
          }
        >
          {children}
        </NextIntlClientProvider>
      </TimeZonesContext.Provider>
    </DisplayContext.Provider>
  );
}

export function useDisplayTimeZones(): readonly string[] {
  return useContext(TimeZonesContext);
}

export function useDisplayPreferences(): DisplayPreferences {
  const preferences = useContext(DisplayContext);
  if (!preferences) throw new Error('Missing display preferences provider');
  return preferences;
}
