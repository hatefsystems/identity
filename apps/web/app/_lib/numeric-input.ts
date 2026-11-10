// Convert only the two supported native digit ranges; strict validators still
// reject all other characters and preserve leading zeroes.
export function normalizeNumericInput(value: string): string {
  return value.replace(/[\u0660-\u0669\u06f0-\u06f9]/g, (digit) =>
    String(digit.charCodeAt(0) - (digit.charCodeAt(0) >= 0x06f0 ? 0x06f0 : 0x0660))
  );
}
