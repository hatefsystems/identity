import { useTranslations } from 'next-intl';

export function QueryUtcTime({ value }: { value: string | null }) {
  const t = useTranslations('audit');
  if (value === null) return <span>{t('notRecorded')}</span>;
  // Date normalizes the zone, but cannot retain the wire's sub-millisecond precision.
  const fraction = value.match(/\.\d+(?=Z$|[+-]\d{2}:\d{2}$)/)?.[0] ?? '';
  return (
    <time dir="ltr" dateTime={value} className="whitespace-normal">
      {new Date(value)
        .toISOString()
        .replace('T', ' ')
        .replace(/\.\d{3}Z$/, `${fraction} UTC`)}
    </time>
  );
}
