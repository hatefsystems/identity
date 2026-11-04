'use client';

import { createContext, useContext, type ReactNode } from 'react';
import { NextIntlClientProvider } from 'next-intl';
import { timeZones as defaultTimeZones, type DisplayPreferences } from './config';
import type { Messages } from './messages';
import { formats } from './formats';
import { commonEn, commonFa } from '../messages/common';

const DisplayContext = createContext<DisplayPreferences | undefined>(undefined);
const TimeZonesContext = createContext<readonly string[]>(defaultTimeZones);

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
