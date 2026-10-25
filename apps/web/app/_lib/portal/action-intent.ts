export type PasskeyAction =
  { kind: 'add'; name: string } | { kind: 'rename' | 'remove'; id: string; name: string };

// Deliberately excludes profile snapshots, codes, challenges and authorization.
// Names here are proposed mutation parameters, not a cached credential listing.
export type StepUpIntent = { kind: 'passkey'; action: PasskeyAction } | { kind: 'recovery' };
