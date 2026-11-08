export const locales = ['en', 'fa-IR'] as const;
export type Locale = (typeof locales)[number];
export type CalendarPreference = 'auto' | 'gregory' | 'persian';
export type DisplayPreferences = {
  locale: Locale;
  calendar: CalendarPreference;
  timeZone: string;
};

export const preferenceCookie = '__Host-hatef-ui';
export const preferenceMaxAge = 60 * 60 * 24 * 365;
export const preferenceMaxLength = 128;
export const defaultPreferences: DisplayPreferences = {
  locale: 'en',
  calendar: 'auto',
  timeZone: 'UTC',
};

export const timeZones = ['UTC', ...Intl.supportedValuesOf('timeZone')];
const supportedTimeZones = new Set(timeZones);

export function isLocale(value: unknown): value is Locale {
  return value === 'en' || value === 'fa-IR';
}

export function isCalendar(value: unknown): value is CalendarPreference {
  return value === 'auto' || value === 'gregory' || value === 'persian';
}

export function canonicalTimeZone(value: unknown): string | undefined {
  if (
    typeof value !== 'string' ||
    value.length > 64 ||
    !/^[A-Za-z_]+(?:\/[A-Za-z0-9_+-]+){0,2}$/.test(value)
  ) {
    return undefined;
  }
  try {
    const canonical = new Intl.DateTimeFormat('en', { timeZone: value }).resolvedOptions().timeZone;
    return supportedTimeZones.has(canonical) ? canonical : undefined;
  } catch {
    return undefined;
  }
}

export function resolvedCalendar(preferences: DisplayPreferences): 'gregory' | 'persian' {
  return preferences.calendar === 'auto'
    ? preferences.locale === 'fa-IR'
      ? 'persian'
      : 'gregory'
    : preferences.calendar;
}

export function parsePreferences(value: string | undefined): DisplayPreferences {
  if (!value || value.length > preferenceMaxLength) return { ...defaultPreferences };
  const parts = value.split('~');
  if (parts.length !== 4 || parts[0] !== '1') return { ...defaultPreferences };
  const [, locale, calendar, timeZone] = parts;
  return {
    locale: isLocale(locale) ? locale : defaultPreferences.locale,
    calendar: isCalendar(calendar) ? calendar : defaultPreferences.calendar,
    timeZone: canonicalTimeZone(timeZone) ?? defaultPreferences.timeZone,
  };
}

export function validatePreferences(value: unknown): DisplayPreferences | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(',') !== 'calendar,locale,timeZone' ||
    !isLocale(record.locale) ||
    !isCalendar(record.calendar)
  )
    return undefined;
  const timeZone = canonicalTimeZone(record.timeZone);
  return timeZone ? { locale: record.locale, calendar: record.calendar, timeZone } : undefined;
}

export function serializePreferences(preferences: DisplayPreferences): string {
  return `1~${preferences.locale}~${preferences.calendar}~${preferences.timeZone}`;
}

export function hasDuplicatePreferenceCookie(header: string | null): boolean {
  let count = 0;
  for (const part of (header ?? '').split(';')) {
    const equal = part.indexOf('=');
    if (equal !== -1 && part.slice(0, equal).trim() === preferenceCookie && ++count > 1)
      return true;
  }
  return false;
}
