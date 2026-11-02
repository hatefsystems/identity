export type PasskeyAction =
  { kind: 'add'; name: string } | { kind: 'rename' | 'remove'; id: string; name: string };

export type LegalOperation = 'hold' | 'preservation' | 'release' | 'lookup';

// Deliberately excludes profile snapshots, codes, challenges and authorization.
// Names here are proposed mutation parameters, not a cached credential listing.
export type StepUpIntent =
  | { kind: 'passkey'; action: PasskeyAction }
  | { kind: 'recovery' }
  | { kind: 'moderation'; status: 'active' | 'suspended' | 'banned' }
  // An operation name only: never a legal reference, query, draft, key or cursor.
  | { kind: 'legal'; operation: LegalOperation };
