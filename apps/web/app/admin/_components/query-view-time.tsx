export function QueryUtcTime({ value }: { value: string | null }) {
  if (value === null) return <span>Not recorded</span>;
  // Date normalizes the zone, but cannot retain the wire's sub-millisecond precision.
  const fraction = value.match(/\.\d+(?=Z$|[+-]\d{2}:\d{2}$)/)?.[0] ?? '';
  return (
    <time dateTime={value} className="whitespace-normal">
      {new Date(value)
        .toISOString()
        .replace('T', ' ')
        .replace(/\.\d{3}Z$/, `${/^\.0+$/.test(fraction) ? '' : fraction} UTC`)}
    </time>
  );
}
