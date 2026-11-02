'use client';

import { Button, Input, Label } from '@hatef/ui';
import { useEffect, useId, useRef, useState, type ChangeEvent } from 'react';
import { controlClass, inputClass } from '../../_components/controls';
import { usePortal } from '../../_components/portal-provider';
import { StepUpDialog } from '../../_components/step-up-dialog';
import { LegalClient } from '../../_lib/admin/legal-api';
import type {
  LegalDisclosureField,
  LegalHold,
  LegalHoldRequest,
  LegalLookupContinuation,
  LegalLookupPage,
  LegalLookupQuery,
  LegalPreservationRequest,
  LegalPreservationResult,
} from '../../_lib/admin/legal-contracts';
import {
  legalPageLimits,
  validateLegalHoldRequest,
  validateLegalLookupQuery,
  validateLegalPreservationRequest,
} from '../../_lib/admin/legal-validation';
import type { LegalOperation } from '../../_lib/portal/action-intent';
import type { StepUpGrant } from '../../_lib/portal/contracts';
import { isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import { clearLegalControls, clearLegalRegion, legalFieldLabels } from './legal-view-state';

export type LegalAction =
  | { kind: 'hold' | 'preservation'; accountRef?: string }
  | { kind: 'release'; hold: LegalHold }
  | { kind: 'lookup'; continuation?: LegalLookupContinuation };

export type LegalOutcome =
  | { kind: 'created'; hold: LegalHold; observation?: LegalPreservationResult }
  | { kind: 'released'; holdId: string }
  | { kind: 'lookup'; query: LegalLookupQuery; page: LegalLookupPage }
  | { kind: 'cancelled' | 'expired' | 'unconfirmed'; operation: LegalOperation }
  | { kind: 'failed'; operation: LegalOperation; error: unknown };

type Prepared =
  | { kind: 'hold'; request: LegalHoldRequest }
  | { kind: 'preservation'; request: LegalPreservationRequest }
  | { kind: 'release'; holdId: string; accountRef: string }
  | { kind: 'lookup'; query: LegalLookupQuery };

const emptyDraft = () => ({
  accountRef: '',
  requestId: '',
  reason: '',
  requestingAuthority: '',
  legalBasis: '',
  date: '',
  identifier: '',
  caseReference: '',
  purpose: '',
  startTime: '',
  endTime: '',
  size: '',
});
type Draft = ReturnType<typeof emptyDraft>;
const titles: Record<LegalOperation, string> = {
  hold: 'Apply Legal Hold',
  preservation: 'Record preservation',
  release: 'Release Legal Hold request',
  lookup: 'Attribution inquiry',
};
const confirmations: Record<LegalOperation, string> = {
  hold: 'Confirm Legal Hold',
  preservation: 'Confirm preservation',
  release: 'Confirm release',
  lookup: 'Confirm lookup',
};

export function LegalActionDialog({
  action,
  resumeTotp = false,
  onOutcome,
}: {
  action: LegalAction;
  resumeTotp?: boolean;
  onOutcome: (outcome: LegalOutcome) => void;
}) {
  const { client, profile, capabilities, reportPermissionLoss, reportLegalInterruption } =
    usePortal();
  const [deadline, setDeadline] = useState<number | null>(null);
  const [draft, setDraft] = useState(emptyDraft);
  const [fields, setFields] = useState<LegalDisclosureField[]>([]);
  const [prepared, setPrepared] = useState<Prepared | null>(null);
  const [error, setError] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const region = useRef<HTMLDivElement>(null);
  const form = useRef<HTMLFormElement>(null);
  const settled = useRef(false);
  const id = useId();
  const waiting = useRef<{
    grant: StepUpGrant;
    signal: AbortSignal;
    sent: boolean;
    submitting: boolean;
    finish: () => void;
    timer: ReturnType<typeof setTimeout>;
    abort: () => void;
  } | null>(null);

  useEffect(() => {
    const element = region.current;
    return () => {
      clearLegalRegion(element);
      const operation = waiting.current;
      waiting.current = null;
      const interrupted = !settled.current && operation?.sent;
      settled.current = true;
      if (operation) {
        operation.signal.removeEventListener('abort', operation.abort);
        clearTimeout(operation.timer);
        operation.grant.clear();
        operation.finish();
      }
      if (interrupted) reportLegalInterruption(action.kind);
    };
  }, [action.kind, reportLegalInterruption]);

  useEffect(() => {
    if (deadline) {
      const control = form.current?.querySelector<HTMLElement>('input:not(:disabled), textarea');
      control?.focus();
    }
  }, [deadline, prepared]);

  function finish(outcome: LegalOutcome) {
    if (settled.current) return;
    settled.current = true;
    const operation = waiting.current;
    waiting.current = null;
    if (operation) {
      operation.signal.removeEventListener('abort', operation.abort);
      clearTimeout(operation.timer);
      operation.grant.clear();
      operation.finish();
    }
    clearLegalRegion(region.current);
    setDraft(emptyDraft());
    setFields([]);
    setPrepared(null);
    setAcknowledged(false);
    if (outcome.kind === 'unconfirmed') reportLegalInterruption(action.kind);
    onOutcome(outcome);
  }

  function cancel() {
    finish({ kind: waiting.current?.sent ? 'unconfirmed' : 'cancelled', operation: action.kind });
  }

  async function authorized(grant: StepUpGrant, signal: AbortSignal) {
    throwIfAborted(signal);
    client.assertSession();
    if (!capabilities || settled.current) return;
    const end = Math.min(grant.deadline, Date.parse(profile.session.expires_at));
    if (Date.now() >= end) {
      finish({ kind: 'expired', operation: action.kind });
      return;
    }
    setDraft({
      ...emptyDraft(),
      accountRef:
        action.kind === 'hold' || action.kind === 'preservation' ? (action.accountRef ?? '') : '',
      size: String(legalPageLimits(capabilities.limits).default),
    });
    if (action.kind === 'release')
      setPrepared({ kind: 'release', holdId: action.hold.id, accountRef: action.hold.account_ref });
    else if (action.kind === 'lookup' && action.continuation)
      setPrepared({ kind: 'lookup', query: action.continuation.query });
    // StepUpDialog owns this grant until final confirmation, expiry or cancellation.
    await new Promise<void>((resolve) => {
      const abort = () =>
        finish({
          kind: waiting.current?.sent ? 'unconfirmed' : 'cancelled',
          operation: action.kind,
        });
      const timer = setTimeout(
        () =>
          finish({
            kind: waiting.current?.sent ? 'unconfirmed' : 'expired',
            operation: action.kind,
          }),
        Math.max(0, end - Date.now())
      );
      waiting.current = {
        grant,
        signal,
        sent: false,
        submitting: false,
        finish: resolve,
        timer,
        abort,
      };
      signal.addEventListener('abort', abort, { once: true });
      setDeadline(end);
    });
  }

  function prepare() {
    if (!waiting.current || waiting.current.submitting || settled.current || !capabilities) return;
    try {
      let value: Prepared;
      if (action.kind === 'hold') {
        value = {
          kind: 'hold',
          request: validateLegalHoldRequest({
            accountRef: action.accountRef ?? draft.accountRef,
            requestId: draft.requestId,
            reason: draft.reason,
            requestingAuthority: draft.requestingAuthority,
            legalBasis: draft.legalBasis,
            reviewAt: draft.date,
          }),
        };
      } else if (action.kind === 'preservation') {
        value = {
          kind: 'preservation',
          request: validateLegalPreservationRequest({
            accountRef: action.accountRef ?? draft.accountRef,
            requestId: draft.requestId,
            reason: draft.reason,
            requestingAuthority: draft.requestingAuthority,
            expiresAt: draft.date,
          }),
        };
      } else if (action.kind === 'lookup') {
        value = {
          kind: 'lookup',
          query: validateLegalLookupQuery(
            {
              identifier: draft.identifier,
              requestingAuthority: draft.requestingAuthority,
              caseReference: draft.caseReference,
              purpose: draft.purpose,
              startTime: draft.startTime,
              endTime: draft.endTime,
              limit: /^[1-9][0-9]*$/.test(draft.size) ? Number(draft.size) : 0,
              fields,
            },
            capabilities.limits
          ),
        };
      } else return;
      // Keep the immutable normalized tuple, not live/detached input controls.
      clearLegalControls(form.current);
      setPrepared(value);
      setDraft(emptyDraft());
      setFields([]);
      setError('');
    } catch {
      setError(
        action.kind === 'lookup'
          ? 'Use a bare email of at most 320 UTF-8 bytes, authority and case reference of 1-255 bytes, purpose of 1-4096 bytes, explicit ordered RFC3339 UTC bounds within the configured window, and an allowed page size.'
          : 'Use canonical nonzero UUIDs, a reason of 1-4096 UTF-8 bytes, authority and legal basis of 1-255 bytes where required, and an optional RFC3339 UTC date with at most six fractional digits. Blank narratives are invalid.'
      );
      form.current?.querySelector<HTMLElement>('input:not(:disabled), textarea')?.focus();
    }
  }

  async function submit() {
    const operation = waiting.current;
    if (!operation || operation.submitting || settled.current || !prepared || !acknowledged) return;
    if (!deadline || Date.now() >= deadline) {
      finish({ kind: 'expired', operation: action.kind });
      return;
    }
    operation.submitting = true;
    setSubmitting(true);
    const onSend = () => {
      throwIfAborted(operation.signal);
      if (waiting.current !== operation || settled.current)
        throw new DOMException('Cancelled', 'AbortError');
      operation.sent = true;
    };
    try {
      const api = new LegalClient(client);
      let result: LegalOutcome;
      if (prepared.kind === 'hold') {
        const hold = await api.applyHold(
          prepared.request,
          operation.grant,
          operation.signal,
          onSend
        );
        result = { kind: 'created', hold };
      } else if (prepared.kind === 'preservation') {
        const observation = await api.preserve(
          prepared.request,
          operation.grant,
          operation.signal,
          onSend
        );
        result = { kind: 'created', hold: observation.hold, observation };
      } else if (prepared.kind === 'release') {
        await api.releaseHold(prepared.holdId, operation.grant, operation.signal, onSend);
        result = { kind: 'released', holdId: prepared.holdId };
      } else {
        const page = await api.lookup(
          prepared.query,
          operation.grant,
          operation.signal,
          onSend,
          action.kind === 'lookup' ? action.continuation : undefined
        );
        result = { kind: 'lookup', query: prepared.query, page };
      }
      if (waiting.current !== operation || settled.current) return;
      finish(operation.signal.aborted ? { kind: 'unconfirmed', operation: action.kind } : result);
    } catch (failure) {
      if (waiting.current !== operation || settled.current) return;
      if (
        operation.sent &&
        (operation.signal.aborted ||
          isAborted(failure) ||
          !(failure instanceof PortalError) ||
          failure.uncertain ||
          failure.status >= 500 ||
          failure.status === 401 ||
          failure.code === 'session_changed')
      ) {
        finish({ kind: 'unconfirmed', operation: action.kind });
      } else {
        finish({ kind: 'failed', operation: action.kind, error: failure });
        if (
          failure instanceof PortalError &&
          failure.status === 403 &&
          failure.code !== 'insufficient_user_authentication'
        )
          reportPermissionLoss();
      }
    }
  }

  function field(name: keyof Draft, label: string, multiline = false, disabled = false) {
    const props = {
      id: `${id}-${name}`,
      name,
      value: draft[name],
      disabled,
      autoComplete: 'off',
      spellCheck: false,
      'aria-invalid': Boolean(error),
      'aria-describedby': `${id}-input-help${error ? ` ${id}-error` : ''}`,
      onChange: (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        setDraft({ ...draft, [name]: event.target.value });
        setError('');
      },
    };
    return (
      <div key={name} className="min-w-0 space-y-2">
        <Label htmlFor={props.id}>{label}</Label>
        {multiline ? (
          <textarea
            {...props}
            rows={4}
            className={`${inputClass} min-h-28 w-full resize-y rounded-md border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring`}
          />
        ) : (
          <Input {...props} type="text" autoCapitalize="none" className={`${inputClass} w-full`} />
        )}
      </div>
    );
  }

  const create = action.kind === 'hold' || action.kind === 'preservation';
  const pinnedAccount = 'accountRef' in action ? action.accountRef : undefined;
  const summary: [string, string][] = !prepared
    ? []
    : prepared.kind === 'release'
      ? [
          ['Hold request UUID', prepared.holdId],
          ['Original account reference', prepared.accountRef],
        ]
      : prepared.kind === 'lookup'
        ? [
            ['Transient email input (not evidence)', prepared.query.identifier],
            ['Requesting authority', prepared.query.requestingAuthority],
            ['Case reference', prepared.query.caseReference],
            ['Inquiry purpose', prepared.query.purpose],
            ['Start time (UTC)', prepared.query.startTime],
            ['End time (UTC)', prepared.query.endTime],
            ['Page size', String(prepared.query.limit)],
            [
              'Additional disclosure fields',
              prepared.query.fields.map((key) => legalFieldLabels[key]).join(', ') ||
                'None (core metadata only)',
            ],
          ]
        : [
            ['Request kind', prepared.kind === 'hold' ? 'Legal Hold' : 'Preservation request'],
            ['Original account reference', prepared.request.accountRef],
            ['Operation UUID', prepared.request.requestId],
            ['Reason', prepared.request.reason],
            ['Requesting authority', prepared.request.requestingAuthority],
            [
              'Legal basis',
              prepared.kind === 'hold'
                ? prepared.request.legalBasis
                : 'preservation_request (server fixed)',
            ],
            [
              prepared.kind === 'hold' ? 'Review at (UTC)' : 'Expires at (UTC)',
              (prepared.kind === 'hold' ? prepared.request.reviewAt : prepared.request.expiresAt) ||
                'Not supplied',
            ],
          ];

  return (
    <div ref={region}>
      <StepUpDialog
        title={titles[action.kind]}
        description={
          <p>
            Verify first, then review the exact legal operation and confirm explicitly. Verification
            is one-use and expires. Cancellation or leaving this workflow clears its sensitive data.
          </p>
        }
        onCancel={cancel}
        onAuthorized={authorized}
        intent={{ kind: 'legal', operation: action.kind }}
        resumeMethod={resumeTotp ? 'totp' : undefined}
        verifiedStatus={
          submitting
            ? 'Sending one legal request. Do not submit again.'
            : 'Verification complete. Review and confirm before verification expires.'
        }
        verifiedContent={
          deadline && (
            <div className="min-w-0 space-y-4" data-legal-private>
              <p className="text-sm text-muted-foreground">
                Single-use verification expires at{' '}
                <time dateTime={new Date(deadline).toISOString()}>
                  {new Date(deadline).toLocaleTimeString()}
                </time>
                . Expiry clears the form and requires fresh verification.
              </p>
              {!prepared ? (
                <form
                  ref={form}
                  aria-label="Prepare legal request"
                  method="post"
                  noValidate
                  autoComplete="off"
                  className="min-w-0 space-y-4"
                  onSubmit={(event) => {
                    event.preventDefault();
                    prepare();
                  }}
                >
                  {create ? (
                    <>
                      {field(
                        'accountRef',
                        'Original account reference',
                        false,
                        Boolean(pinnedAccount)
                      )}
                      {field('requestId', 'Operation UUID')}
                      {field('reason', 'Reason', true)}
                      {field('requestingAuthority', 'Requesting authority')}
                      {action.kind === 'hold' && field('legalBasis', 'Legal basis')}
                      {field(
                        'date',
                        action.kind === 'hold' ? 'Review at (UTC)' : 'Expires at (UTC)'
                      )}
                      <p id={`${id}-input-help`} className="text-sm text-muted-foreground">
                        Use the original account_ref from controlled intake, not an email or a
                        profile lookup. Record your operation UUID and exact normalized inputs in
                        that external record. The browser does not generate a UUID or keep a
                        recovery draft. Reason: 1-4096 UTF-8 bytes; authority and legal basis:
                        1-255. Optional date: RFC3339 UTC ending in Z, at most six fractional
                        digits; past dates are allowed. Dates never release a hold automatically.
                      </p>
                    </>
                  ) : (
                    <>
                      {field('identifier', 'Email for attribution')}
                      {field('requestingAuthority', 'Requesting authority')}
                      {field('caseReference', 'Case reference')}
                      {field('purpose', 'Inquiry purpose', true)}
                      {field('startTime', 'Start time (UTC)')}
                      {field('endTime', 'End time (UTC)')}
                      {field('size', 'Page size')}
                      <p id={`${id}-input-help`} className="text-sm text-muted-foreground">
                        Bare email up to 320 UTF-8 bytes; authority and case reference 1-255;
                        purpose 1-4096. Enter explicit RFC3339 UTC bounds ending in Z. Maximum
                        window: {capabilities?.limits.audit_max_window_seconds} seconds. Page size:
                        1-{capabilities ? legalPageLimits(capabilities.limits).max : 1}. No
                        provider-specific email normalization is performed here.
                      </p>
                      <fieldset className="min-w-0 space-y-2 rounded-md border p-3">
                        <legend className="px-1 text-sm font-semibold">
                          Additional disclosure for this inquiry purpose
                        </legend>
                        {(Object.keys(legalFieldLabels) as LegalDisclosureField[]).map((key) => (
                          <label
                            key={key}
                            className="flex min-h-11 items-center gap-3 py-2 text-sm"
                          >
                            <input
                              type="checkbox"
                              checked={fields.includes(key)}
                              onChange={(event) =>
                                setFields(
                                  event.target.checked
                                    ? [...fields, key]
                                    : fields.filter((item) => item !== key)
                                )
                              }
                              className="size-5 shrink-0 accent-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                            />
                            {legalFieldLabels[key]}
                          </label>
                        ))}
                        <p className="text-sm text-muted-foreground">
                          All optional fields start unchecked. Only explicitly selected supported
                          metadata is requested.
                        </p>
                      </fieldset>
                    </>
                  )}
                  {error && (
                    <p id={`${id}-error`} role="alert" className="text-sm text-destructive">
                      {error}
                    </p>
                  )}
                  <Button type="submit" className={`${controlClass} w-full`}>
                    Review request
                  </Button>
                </form>
              ) : (
                <form
                  ref={form}
                  aria-label="Confirm legal request"
                  method="post"
                  noValidate
                  className="min-w-0 space-y-4"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void submit();
                  }}
                >
                  <dl className="min-w-0 space-y-3 text-sm">
                    {summary.map(([label, value]) => (
                      <div key={label} className="min-w-0">
                        <dt className="text-muted-foreground">{label}</dt>
                        <dd className="mt-1 whitespace-pre-wrap break-all">{value}</dd>
                      </div>
                    ))}
                  </dl>
                  <p className="text-sm leading-relaxed">
                    {action.kind === 'release'
                      ? 'Release affects only this immutable hold request UUID. Other holds may remain. Original retention clocks resume, which may allow immediate eligibility at the next purge; release never resets retention. A 204 also covers an already released request and does not prove this caller changed it.'
                      : action.kind === 'lookup'
                        ? 'Class B records are pseudonymized personal data, not anonymous. An indexed match is not verified real-world identity or permission to disclose externally. Sequence position is not an inclusion proof. This request is for one page only.'
                        : 'Each request is independent. Holds override retention until explicit release; review and expiry dates are advisory. A hold cannot restore erased data, extend account recovery, or create an immutable evidence snapshot.'}
                  </p>
                  {create && (
                    <p className="text-sm text-muted-foreground">
                      Idempotency is scoped to the original reference, request kind, and UUID, not
                      the actor or a global UUID. Changing target or kind creates another
                      independent hold. Exact replay may return an already released request and
                      never reactivates it; a cleaned narrative tombstone conflicts instead of
                      recreating it. Preserve this exact normalized tuple in controlled external
                      intake before confirming.
                    </p>
                  )}
                  <label className="flex min-h-11 items-start gap-3 py-2 text-sm leading-relaxed">
                    <input
                      type="checkbox"
                      checked={acknowledged}
                      disabled={submitting}
                      onChange={(event) => setAcknowledged(event.target.checked)}
                      className="mt-1 size-5 shrink-0 accent-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    />
                    {create
                      ? 'I reviewed the target, operation UUID, request kind, and normalized inputs.'
                      : action.kind === 'release'
                        ? 'I reviewed this hold request UUID and the release consequences.'
                        : 'I reviewed the inquiry purpose, fixed scope, and selected disclosure fields.'}
                  </label>
                  <Button
                    type="submit"
                    className={`${controlClass} w-full`}
                    disabled={!acknowledged || submitting}
                  >
                    {submitting ? 'Submitting legal request...' : confirmations[action.kind]}
                  </Button>
                  <p className="text-sm text-muted-foreground">
                    Inputs are now frozen. To change the target or scope, cancel and start fresh
                    verification. Nothing retries automatically after transmission.
                  </p>
                </form>
              )}
            </div>
          )
        }
      />
    </div>
  );
}
