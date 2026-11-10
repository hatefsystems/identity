'use client';

import { Button, Input, Label } from '@hatef/ui';
import { useTranslations } from 'next-intl';
import { useEffect, useId, useRef, useState, type ChangeEvent, type ReactNode } from 'react';
import type { Message } from '../../../i18n/messages';
import { useMessage } from '../../../i18n/use-message';
import type { legalEn } from '../../../messages/legal';
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
import { QueryUtcTime } from './query-view-time';

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
type FieldLabel = keyof typeof legalEn.fields;

export function LegalActionDialog({
  action,
  resumeTotp = false,
  onOutcome,
}: {
  action: LegalAction;
  resumeTotp?: boolean;
  onOutcome: (outcome: LegalOutcome) => void;
}) {
  const t = useTranslations('legal');
  const message = useMessage();
  const { client, profile, capabilities, reportPermissionLoss, reportLegalInterruption } =
    usePortal();
  const [deadline, setDeadline] = useState<number | null>(null);
  const [draft, setDraft] = useState(emptyDraft);
  const [fields, setFields] = useState<LegalDisclosureField[]>([]);
  const [prepared, setPrepared] = useState<Prepared | null>(null);
  const [error, setError] = useState<Message>('');
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
          ? { key: 'legal.action.invalidLookup' }
          : { key: 'legal.action.invalidCreate' }
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

  function field(name: keyof Draft, label: FieldLabel, multiline = false, disabled = false) {
    const props = {
      id: `${id}-${name}`,
      name,
      value: draft[name],
      disabled,
      dir: [
        'accountRef',
        'requestId',
        'identifier',
        'date',
        'startTime',
        'endTime',
        'size',
      ].includes(name)
        ? 'ltr'
        : 'auto',
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
        <Label htmlFor={props.id}>{t(`fields.${label}`)}</Label>
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
  const summary: [FieldLabel, ReactNode][] = !prepared
    ? []
    : prepared.kind === 'release'
      ? [
          [
            'holdId',
            <bdi dir="ltr" key="holdId">
              {prepared.holdId}
            </bdi>,
          ],
          [
            'accountRef',
            <bdi dir="ltr" key="accountRef">
              {prepared.accountRef}
            </bdi>,
          ],
        ]
      : prepared.kind === 'lookup'
        ? [
            [
              'transientEmail',
              <bdi dir="ltr" key="identifier">
                {prepared.query.identifier}
              </bdi>,
            ],
            [
              'requestingAuthority',
              <bdi dir="auto" key="authority">
                {prepared.query.requestingAuthority}
              </bdi>,
            ],
            [
              'caseReference',
              <bdi dir="auto" key="case">
                {prepared.query.caseReference}
              </bdi>,
            ],
            [
              'purpose',
              <bdi dir="auto" key="purpose">
                {prepared.query.purpose}
              </bdi>,
            ],
            ['startTime', <QueryUtcTime key="start" value={prepared.query.startTime} />],
            ['endTime', <QueryUtcTime key="end" value={prepared.query.endTime} />],
            [
              'size',
              <bdi dir="ltr" key="size">
                {prepared.query.limit}
              </bdi>,
            ],
            [
              'disclosure',
              prepared.query.fields.length ? (
                <ul>
                  {prepared.query.fields.map((key) => (
                    <li key={key}>{t(legalFieldLabels[key])}</li>
                  ))}
                </ul>
              ) : (
                t('values.coreOnly')
              ),
            ],
          ]
        : [
            [
              'requestKind',
              t(prepared.kind === 'hold' ? 'values.hold' : 'values.preservationRequest'),
            ],
            [
              'accountRef',
              <bdi dir="ltr" key="accountRef">
                {prepared.request.accountRef}
              </bdi>,
            ],
            [
              'requestId',
              <bdi dir="ltr" key="requestId">
                {prepared.request.requestId}
              </bdi>,
            ],
            [
              'reason',
              <bdi dir="auto" key="reason">
                {prepared.request.reason}
              </bdi>,
            ],
            [
              'requestingAuthority',
              <bdi dir="auto" key="authority">
                {prepared.request.requestingAuthority}
              </bdi>,
            ],
            [
              'legalBasis',
              prepared.kind === 'hold' ? (
                <bdi dir="auto">{prepared.request.legalBasis}</bdi>
              ) : (
                t.rich('values.serverFixed', { kind: 'preservation_request', value: (chunks) => <bdi dir="ltr">{chunks}</bdi> })
              ),
            ],
            [
              prepared.kind === 'hold' ? 'reviewAt' : 'expiresAt',
              (
                prepared.kind === 'hold' ? prepared.request.reviewAt : prepared.request.expiresAt
              ) ? (
                <QueryUtcTime
                  value={
                    prepared.kind === 'hold'
                      ? (prepared.request.reviewAt ?? null)
                      : (prepared.request.expiresAt ?? null)
                  }
                />
              ) : (
                t('values.notSupplied')
              ),
            ],
          ];

  return (
    <div ref={region}>
      <StepUpDialog
        layout="review"
        title={t(`action.titles.${action.kind}`)}
        description={<p>{t('action.description')}</p>}
        onCancel={cancel}
        onAuthorized={authorized}
        intent={{ kind: 'legal', operation: action.kind }}
        resumeMethod={resumeTotp ? 'totp' : undefined}
        verifiedStatus={
          submitting ? { key: 'legal.action.sending' } : { key: 'legal.action.verified' }
        }
        verifiedActions={
          deadline && (
            <Button
              type="submit"
              form={`${id}-${prepared ? 'confirm' : 'prepare'}`}
              className={`${controlClass} w-full`}
              disabled={Boolean(prepared) && (!acknowledged || submitting)}
            >
              {prepared
                ? t(submitting ? 'action.submitting' : `action.confirmations.${action.kind}`)
                : t('action.review')}
            </Button>
          )
        }
        verifiedContent={
          deadline && (
            <div className="min-w-0 space-y-4" data-legal-private>
              <p className="text-sm text-muted-foreground">
                {t.rich('action.expiry', {
                  time: () => <QueryUtcTime value={new Date(deadline).toISOString()} />,
                })}
              </p>
              {!prepared ? (
                <form
                  id={`${id}-prepare`}
                  ref={form}
                  aria-label={t('action.prepare')}
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
                      {field('accountRef', 'accountRef', false, Boolean(pinnedAccount))}
                      {field('requestId', 'requestId')}
                      {field('reason', 'reason', true)}
                      {field('requestingAuthority', 'requestingAuthority')}
                      {action.kind === 'hold' && field('legalBasis', 'legalBasis')}
                      {field('date', action.kind === 'hold' ? 'reviewAt' : 'expiresAt')}
                      <p id={`${id}-input-help`} className="text-sm text-muted-foreground">
                        {t.rich('action.createHelp', {
                          id: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
                        })}
                      </p>
                    </>
                  ) : (
                    <>
                      {field('identifier', 'identifier')}
                      {field('requestingAuthority', 'requestingAuthority')}
                      {field('caseReference', 'caseReference')}
                      {field('purpose', 'purpose', true)}
                      {field('startTime', 'startTime')}
                      {field('endTime', 'endTime')}
                      {field('size', 'size')}
                      <p id={`${id}-input-help`} className="text-sm text-muted-foreground">
                        {t('action.lookupHelp', {
                          seconds: String(capabilities?.limits.audit_max_window_seconds ?? 0),
                          max: String(capabilities ? legalPageLimits(capabilities.limits).max : 1),
                        })}
                      </p>
                      <fieldset className="min-w-0 space-y-2 rounded-md border p-3">
                        <legend className="px-1 text-sm font-semibold">
                          {t('action.disclosure')}
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
                            {t(legalFieldLabels[key])}
                          </label>
                        ))}
                        <p className="text-sm text-muted-foreground">
                          {t('action.disclosureHelp')}
                        </p>
                      </fieldset>
                    </>
                  )}
                  {error && (
                    <p id={`${id}-error`} role="alert" className="text-sm text-destructive">
                      {message(error)}
                    </p>
                  )}
                </form>
              ) : (
                <form
                  id={`${id}-confirm`}
                  ref={form}
                  aria-label={t('action.confirm')}
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
                        <dt className="text-muted-foreground">{t(`fields.${label}`)}</dt>
                        <dd className="mt-1 whitespace-pre-wrap break-all">{value}</dd>
                      </div>
                    ))}
                  </dl>
                  <p className="text-sm leading-relaxed">
                    {t(
                      action.kind === 'release'
                        ? 'action.releaseWarning'
                        : action.kind === 'lookup'
                          ? 'action.lookupWarning'
                          : 'action.createWarning'
                    )}
                  </p>
                  {create && (
                    <p className="text-sm text-muted-foreground">
                      {t('action.idempotencyWarning')}
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
                    {t(
                      create
                        ? 'action.acknowledgeCreate'
                        : action.kind === 'release'
                          ? 'action.acknowledgeRelease'
                          : 'action.acknowledgeLookup'
                    )}
                  </label>
                  <p className="text-sm text-muted-foreground">{t('action.frozen')}</p>
                </form>
              )}
            </div>
          )
        }
      />
    </div>
  );
}
