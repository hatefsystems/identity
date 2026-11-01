import { PortalError } from '../portal/errors';
import { integer } from '../portal/validation';
import {
  verificationResponse,
  type AdminChain,
  type AdminVerification,
  type AdminVerifyQuery,
} from './contracts';
import { positiveInteger, validateVerifyQuery } from './validation';

export type VerificationRun = {
  chain: AdminChain;
  limit: number;
  through_seq: string | null;
  checked: number;
  erased_checked: number;
  pages: number;
  result: AdminVerification | null;
  next: AdminVerifyQuery | null;
};

export function verificationPageResponse(
  value: unknown,
  chain: AdminChain,
  query: AdminVerifyQuery
): AdminVerification {
  const page = verificationResponse(value);
  const request = validateVerifyQuery(query);
  const source =
    request.predecessor_hash !== undefined
      ? 'supplied_predecessor'
      : request.after_seq === '0'
        ? 'genesis'
        : 'database_predecessor';
  if (
    page.chain !== chain ||
    page.after_seq !== request.after_seq ||
    (request.through_seq !== undefined && page.through_seq !== request.through_seq) ||
    page.checked > (request.limit ?? 1000) ||
    page.seed_source !== source ||
    (request.predecessor_hash !== undefined && page.seed_hash !== request.predecessor_hash)
  )
    throw new PortalError('invalid_response');
  return page;
}

export function beginVerificationRun(chain: AdminChain, maxLimit: number): VerificationRun {
  if (chain !== 'audit' && chain !== 'ledger') throw new PortalError('invalid_request');
  const limit = Math.min(1000, positiveInteger(maxLimit, 5000));
  return {
    chain,
    limit,
    through_seq: null,
    checked: 0,
    erased_checked: 0,
    pages: 0,
    result: null,
    next: { after_seq: '0', limit },
  };
}

// Only the last page and aggregate counts are retained. Callers must discard
// replaced/aborted async runs before passing their response here.
export function advanceVerificationRun(
  run: VerificationRun,
  value: AdminVerification
): VerificationRun {
  if (run.next === null) throw new PortalError('invalid_response');
  const page = verificationPageResponse(value, run.chain, run.next);
  if (
    (run.through_seq !== null && run.through_seq !== page.through_seq) ||
    (run.result !== null && run.result.scope !== page.scope)
  )
    throw new PortalError('invalid_response');
  return {
    chain: run.chain,
    limit: run.limit,
    through_seq: page.through_seq,
    checked: integer(run.checked + page.checked, Number.MAX_SAFE_INTEGER),
    erased_checked: integer(
      run.erased_checked + (page.erased_checked ?? 0),
      Number.MAX_SAFE_INTEGER
    ),
    pages: integer(run.pages + 1, Number.MAX_SAFE_INTEGER),
    result: page,
    next:
      page.verified && !page.complete
        ? {
            after_seq: page.next_after_seq as string,
            through_seq: page.through_seq,
            predecessor_hash: page.last_hash,
            limit: run.limit,
          }
        : null,
  };
}
