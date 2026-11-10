'use client';

import { useId, useRef, useState, useSyncExternalStore, useTransition } from 'react';
import { useTranslations } from 'next-intl';
import { Button } from '@hatef/ui';
import { saveDisplayPreferences } from './actions';
import { canonicalTimeZone, isTheme, type DisplayPreferences } from './config';
import { useDisplayPreferences, useDisplayTimeZones } from './provider';

const subscribe = () => () => undefined;
const selectClass =
  'h-11 min-w-0 max-w-full rounded-md border border-slate-500 bg-background px-3 text-sm dark:border-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring';

export function PreferenceControls() {
  const t = useTranslations('preferences');
  const preferences = useDisplayPreferences();
  const timeZones = useDisplayTimeZones();
  const id = useId();
  const ready = useSyncExternalStore(
    subscribe,
    () => true,
    () => false
  );
  const saving = useRef(false);
  const [pending, startTransition] = useTransition();
  const [expanded, setExpanded] = useState(false);
  const [status, setStatus] = useState<'saved' | 'failed' | 'unsupportedZone' | ''>('');

  function save(change: Partial<DisplayPreferences>) {
    if (!ready || saving.current) return;
    saving.current = true;
    setStatus('');
    startTransition(async () => {
      try {
        const result = await saveDisplayPreferences({ ...preferences, ...change });
        setStatus(result.ok ? 'saved' : 'failed');
      } catch {
        setStatus('failed');
      } finally {
        saving.current = false;
      }
    });
  }

  function useDeviceZone() {
    try {
      const timeZone = canonicalTimeZone(Intl.DateTimeFormat().resolvedOptions().timeZone);
      if (timeZone) save({ timeZone });
      else setStatus('unsupportedZone');
    } catch {
      setStatus('unsupportedZone');
    }
  }

  return (
    <section aria-label={t('label')} className="min-w-0 space-y-2" data-ui-preferences>
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={`${id}-language`} className="text-sm font-medium">
          {t('language')}
        </label>
        <select
          id={`${id}-language`}
          className={selectClass}
          value={preferences.locale}
          disabled={!ready || pending}
          onChange={(event) => save({ locale: event.target.value === 'fa-IR' ? 'fa-IR' : 'en' })}
        >
          <option value="en" lang="en">
            {t('english')}
          </option>
          <option value="fa-IR" lang="fa-IR">
            {t('persian')}
          </option>
        </select>
      </div>
      <details
        className="min-w-0 max-w-md rounded-md border px-3"
        onToggle={(event) => setExpanded(event.currentTarget.open)}
      >
        <summary className="flex min-h-11 cursor-pointer items-center rounded-sm text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
          {t('displaySettings')}
        </summary>
        <div className="space-y-3 pb-4">
          <p className="text-sm leading-relaxed text-muted-foreground">{t('displayOnly')}</p>
          <div className="grid min-w-0 gap-1">
            <label htmlFor={`${id}-theme`} className="text-sm font-medium">{t('appearance')}</label>
            <select
              id={`${id}-theme`}
              className={selectClass}
              value={preferences.theme}
              disabled={!ready || pending}
              onChange={(event) => {
                if (isTheme(event.target.value)) save({ theme: event.target.value });
              }}
            >
              <option value="system">{t('system')}</option>
              <option value="light">{t('light')}</option>
              <option value="dark">{t('dark')}</option>
            </select>
          </div>
          <div className="grid min-w-0 gap-1">
            <label htmlFor={`${id}-calendar`} className="text-sm font-medium">
              {t('calendar')}
            </label>
            <select
              id={`${id}-calendar`}
              className={selectClass}
              value={preferences.calendar}
              disabled={!ready || pending}
              onChange={(event) => {
                const calendar = event.target.value;
                if (calendar === 'auto' || calendar === 'gregory' || calendar === 'persian')
                  save({ calendar });
              }}
            >
              <option value="auto">{t('automatic')}</option>
              <option value="gregory">{t('gregorian')}</option>
              <option value="persian">{t('jalali')}</option>
            </select>
          </div>
          <div className="grid min-w-0 gap-1">
            <label htmlFor={`${id}-zone`} className="text-sm font-medium">
              {t('timeZone')}
            </label>
            <select
              id={`${id}-zone`}
              className={selectClass}
              dir="ltr"
              value={preferences.timeZone}
              disabled={!ready || pending}
              onChange={(event) => save({ timeZone: event.target.value })}
            >
              {(expanded ? timeZones : [preferences.timeZone]).map((zone) => (
                <option key={zone} value={zone}>
                  {zone}
                </option>
              ))}
            </select>
          </div>
          <Button
            type="button"
            variant="outline"
            className="h-auto min-h-11 whitespace-normal"
            disabled={!ready || pending}
            onClick={useDeviceZone}
          >
            {t('deviceTimeZone')}
          </Button>
        </div>
      </details>
      <p
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className={
          pending || status ? 'max-w-md text-sm leading-relaxed text-muted-foreground' : 'sr-only'
        }
      >
        {pending ? t('saving') : status ? t(status) : ''}
      </p>
    </section>
  );
}
