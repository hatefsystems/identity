/** @jest-environment node */

import {
  canonicalTimeZone,
  defaultPreferences,
  hasDuplicatePreferenceCookie,
  parsePreferences,
  preferenceMaxLength,
  resolvedCalendar,
  serializePreferences,
  timeZones,
  validatePreferences,
} from '../i18n/config';
import { formatDisplayDate } from '../i18n/formats';

describe('bounded browser display preferences', () => {
  it.each([
    undefined,
    '',
    'en',
    '0~fa-IR~auto~UTC',
    '2~fa-IR~auto~UTC',
    '1~fa-IR~auto~UTC~extra',
    'x'.repeat(preferenceMaxLength + 1),
  ])('uses English/automatic/UTC for malformed versioned values: %s', (value) => {
    expect(parsePreferences(value)).toEqual(defaultPreferences);
  });

  it('validates each setting independently with documented defaults', () => {
    expect(parsePreferences('1~fa~persian~Asia/Tehran')).toEqual({
      locale: 'en',
      calendar: 'persian',
      timeZone: 'Asia/Tehran',
    });
    expect(parsePreferences('1~fa-IR~hijri~No/SuchZone')).toEqual({
      locale: 'fa-IR',
      calendar: 'auto',
      timeZone: 'UTC',
    });
    expect(parsePreferences('1~fa-IR~gregory~UTC')).toEqual({
      locale: 'fa-IR',
      calendar: 'gregory',
      timeZone: 'UTC',
    });
  });

  it('keeps the versioned cookie small and roundtrips only display data', () => {
    const preferences = {
      locale: 'fa-IR',
      calendar: 'gregory',
      timeZone: 'America/New_York',
    } as const;
    const cookie = serializePreferences(preferences);
    expect(cookie).toBe('1~fa-IR~gregory~America/New_York');
    expect(cookie.length).toBeLessThanOrEqual(preferenceMaxLength);
    expect(parsePreferences(cookie)).toEqual(preferences);
  });

  it('detects duplicate names from raw headers before a cookie store can collapse them', () => {
    expect(hasDuplicatePreferenceCookie(null)).toBe(false);
    expect(hasDuplicatePreferenceCookie('__Host-hatef-ui=1~en~auto~UTC')).toBe(false);
    expect(
      hasDuplicatePreferenceCookie('__Host-hatef-ui=; other=2; __Host-hatef-ui=1~fa-IR~auto~UTC')
    ).toBe(true);
    expect(hasDuplicatePreferenceCookie('__Host-hatef-ui-extra=1; __Host-hatef-ui=2')).toBe(false);
    expect(hasDuplicatePreferenceCookie('__Host-hatef-ui=1; __Host-hatef-ui=1')).toBe(true);
  });

  it.each([
    null,
    [],
    'fa-IR',
    {},
    { locale: 'fa-IR', calendar: 'auto' },
    { ...defaultPreferences, token: 'private' },
    { ...defaultPreferences, locale: 'fa' },
    { ...defaultPreferences, calendar: 'islamic' },
    { ...defaultPreferences, timeZone: 'No/SuchZone' },
  ])('rejects invalid action input without persisting it', (value) => {
    expect(validatePreferences(value)).toBeUndefined();
  });

  it('rejects inherited preference fields and unrelated own properties', () => {
    const input = Object.assign(Object.create(defaultPreferences), { a: 1, b: 2, c: 3 });
    expect(validatePreferences(input)).toBeUndefined();
  });

  it('canonicalizes supported IANA aliases and rejects offsets or unsafe text', () => {
    expect(canonicalTimeZone('UTC')).toBe('UTC');
    expect(canonicalTimeZone('US/Eastern')).toBe('America/New_York');
    expect(canonicalTimeZone('Asia/Tehran')).toBe('Asia/Tehran');
    for (const value of [
      '+03:30',
      ' UTC',
      '<script>',
      'UTC\r\nSet-Cookie:x',
      'x'.repeat(65),
      null,
      42,
    ]) {
      expect(canonicalTimeZone(value)).toBeUndefined();
    }
    expect(timeZones).toContain('UTC');
    expect(timeZones).toContain('Asia/Tehran');
  });

  it('defaults the calendar by locale while explicit calendar/zone survive switches', () => {
    expect(resolvedCalendar(defaultPreferences)).toBe('gregory');
    expect(resolvedCalendar({ ...defaultPreferences, locale: 'fa-IR' })).toBe('persian');
    for (const locale of ['en', 'fa-IR'] as const) {
      const preferences = validatePreferences({
        locale,
        calendar: 'gregory',
        timeZone: 'Asia/Tehran',
      });
      expect(preferences).toEqual({ locale, calendar: 'gregory', timeZone: 'Asia/Tehran' });
      if (!preferences) throw new Error('Expected supported explicit display preferences');
      expect(resolvedCalendar(preferences)).toBe('gregory');
    }
  });
});

describe('explicit display-only date formatting', () => {
  it('uses Jalali year boundaries only when the selected calendar requests them', () => {
    const preferences = { ...defaultPreferences, calendar: 'persian' } as const;
    expect(formatDisplayDate('2024-03-19T12:00:00Z', preferences)).toContain('1402');
    expect(formatDisplayDate('2024-03-20T12:00:00Z', preferences)).toContain('1403');
    expect(formatDisplayDate('2024-03-20T12:00:00Z', defaultPreferences)).toContain('2024');
  });

  it('has deterministic UTC defaults and respects explicit UTC day boundaries', () => {
    const timestamp = '2024-01-01T23:30:00.123456789Z';
    expect(formatDisplayDate(timestamp, defaultPreferences)).toBe('Jan 1, 2024, 11:30 PM');
    expect(formatDisplayDate(timestamp, { ...defaultPreferences, timeZone: 'Asia/Tehran' })).toBe(
      'Jan 2, 2024, 3:00 AM'
    );
    expect(timestamp).toBe('2024-01-01T23:30:00.123456789Z');
  });

  it('observes DST without altering timestamps or deadline arithmetic', () => {
    const preferences = { ...defaultPreferences, timeZone: 'America/New_York' };
    expect(formatDisplayDate('2024-03-10T06:59:00Z', preferences)).toBe('Mar 10, 2024, 1:59 AM');
    expect(formatDisplayDate('2024-03-10T07:00:00Z', preferences)).toBe('Mar 10, 2024, 3:00 AM');
    expect(Date.parse('2024-03-10T07:00:00Z') - Date.parse('2024-03-10T06:59:00Z')).toBe(60_000);
  });
});
