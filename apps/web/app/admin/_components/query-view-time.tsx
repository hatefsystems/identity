export function QueryUtcTime({ value }: { value: string | null }) {
  if (value === null) return <span>Not recorded</span>;
  return (
    <time dateTime={value} className="whitespace-normal">
      {new Date(value)
        .toISOString()
        .replace('T', ' ')
        .replace('.000Z', ' UTC')
        .replace('Z', ' UTC')}
    </time>
  );
}
