import { resolvedCalendar, type DisplayPreferences } from './config';

export const formats = {
  number: { count: { maximumFractionDigits: 0 } },
  dateTime: { ordinary: { dateStyle: 'medium', timeStyle: 'short' } },
} as const;

export function formatDisplayDate(value: string, preferences: DisplayPreferences): string {
  return new Intl.DateTimeFormat(preferences.locale, {
    ...formats.dateTime.ordinary,
    calendar: resolvedCalendar(preferences),
    timeZone: preferences.timeZone,
  }).format(new Date(value));
}
