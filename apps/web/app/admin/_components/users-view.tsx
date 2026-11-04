'use client';

import { Button, Input, Label } from '@hatef/ui';
import Link from 'next/link';
import { useTranslations } from 'next-intl';
import { useId, useRef, useState, type FormEvent } from 'react';
import type { Message } from '../../../i18n/messages';
import { useMessage } from '../../../i18n/use-message';
import {
  controlClass,
  Feedback,
  inputClass,
  linkClass,
  PageHeading,
  Panel,
} from '../../_components/controls';
import { usePortal } from '../../_components/portal-provider';
import { AdminClient } from '../../_lib/admin/client';
import type {
  AdminCapabilities,
  AdminUsersPage,
  AdminUsersQuery,
  AdminUserStatus,
} from '../../_lib/admin/contracts';
import type { PortalClient } from '../../_lib/portal/client';
import { isAborted, PortalError } from '../../_lib/portal/errors';
import { clearSensitiveViews } from '../../_lib/portal/invalidation';
import {
  queryCellClass,
  queryClearedMessage,
  queryFailureMessage,
  queryHeadClass,
  queryPageSize,
  querySelectClass,
  queryTableFrameClass,
  revealQueryFocus,
  useQueryViewWork,
} from './query-view-state';
import { QueryUtcTime } from './query-view-time';

const accountStatuses = [
  'active',
  'suspended',
  'banned',
  'pending_verification',
  'pending_deletion',
] as const satisfies readonly AdminUserStatus[];
const maxAccountOffset = 2147483647;

export function UsersView() {
  const t = useTranslations('admin');
  const { client, profile, capabilities, reportPermissionLoss } = usePortal();
  return (
    <>
      <PageHeading title={t('accounts.title')}>{t('accounts.description')}</PageHeading>
      {capabilities?.capabilities.users_read ? (
        <AccountQuery
          key={`${profile.session.id}:${capabilities.capabilities.users_pii}:${capabilities.capabilities.users_lookup}`}
          client={client}
          capabilities={capabilities}
          reportPermissionLoss={reportPermissionLoss}
        />
      ) : (
        <Feedback error={{ key: 'admin.accounts.denied' }} />
      )}
    </>
  );
}

function AccountQuery({
  client,
  capabilities,
  reportPermissionLoss,
}: {
  client: PortalClient;
  capabilities: AdminCapabilities;
  reportPermissionLoss: () => void;
}) {
  const t = useTranslations('admin');
  const message = useMessage();
  const { limits } = capabilities;
  const canPII = capabilities.capabilities.users_pii;
  const canLookup = canPII && capabilities.capabilities.users_lookup;
  const [accountStatus, setAccountStatus] = useState<AdminUserStatus | ''>('');
  const [size, setSize] = useState(String(limits.page_size_default));
  const [email, setEmail] = useState('');
  const [page, setPage] = useState<AdminUsersPage | null>(null);
  const [query, setQuery] = useState<AdminUsersQuery | null>(null);
  const [mode, setMode] = useState<'list' | 'lookup' | null>(null);
  const [pending, setPending] = useState(false);
  const [status, setStatus] = useState<Message>({ key: 'admin.accounts.initial' });
  const [error, setError] = useState<Message>('');
  const [sizeError, setSizeError] = useState<Message>('');
  const [emailError, setEmailError] = useState<Message>('');
  const sizeInput = useRef<HTMLInputElement>(null);
  const emailInput = useRef<HTMLInputElement>(null);
  const id = useId();
  const { work, cleared } = useQueryViewWork(() => {
    setPage(null);
    setQuery(null);
    setMode(null);
    setEmail('');
    setAccountStatus('');
    setSize(String(limits.page_size_default));
    setPending(false);
    setStatus('');
    setError('');
    setEmailError('');
    setSizeError('');
  });

  function discardResult() {
    work.cancel();
    setPage(null);
    setQuery(null);
    setMode(null);
    setPending(false);
    setStatus({ key: 'admin.accounts.changed' });
    setError('');
  }

  async function load(request: AdminUsersQuery | string) {
    const controller = work.begin();
    if (!controller) return;
    const lookup = typeof request === 'string';
    setPage(null);
    setQuery(null);
    setMode(lookup ? 'lookup' : 'list');
    setPending(true);
    setError('');
    setStatus({ key: lookup ? 'admin.accounts.lookingUp' : 'admin.accounts.loading' });
    try {
      const api = new AdminClient(client);
      const result = lookup
        ? await api.lookup(request, controller.signal)
        : await api.users(request, controller.signal);
      if (!work.current(controller)) return;
      // Do not retain an unexpected email field in a safe-metadata workspace.
      setPage({
        ...result,
        items: result.items.map((item) => ({ ...item, email: canPII ? item.email : undefined })),
      });
      setQuery(lookup ? null : request);
      setStatus({
        key: lookup ? 'admin.accounts.matchesLoaded' : 'admin.accounts.pageLoaded',
        values: { count: result.items.length },
      });
    } catch (failure) {
      if (!work.current(controller) || isAborted(failure)) return;
      setPage(null);
      setStatus('');
      setError(queryFailureMessage(failure));
      if (failure instanceof PortalError && failure.status === 403) {
        clearSensitiveViews();
        reportPermissionLoss();
      }
    } finally {
      if (work.current(controller)) setPending(false);
      work.finish(controller);
    }
  }

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending || work.blocked) return;
    const limit = queryPageSize(size, limits.page_size_max);
    if (limit === null) {
      setSizeError({ key: 'admin.accounts.sizeError', values: { maximum: limits.page_size_max } });
      sizeInput.current?.focus();
      return;
    }
    setEmail('');
    setEmailError('');
    setSizeError('');
    void load({ limit, offset: 0, ...(accountStatus ? { status: accountStatus } : {}) });
  }

  function lookup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canLookup || pending || work.blocked) return;
    const value = email.trim();
    if (
      !/^[^@\s]+@[^@\s]+$/.test(value) ||
      /[\p{Cc}\p{Cs}]/u.test(value) ||
      new TextEncoder().encode(value).length > 254
    ) {
      setEmailError({ key: 'admin.accounts.emailError' });
      emailInput.current?.focus();
      return;
    }
    setEmailError('');
    void load(value);
  }

  if (cleared) return <Feedback status={queryClearedMessage} />;

  return (
    <Panel title={t('accounts.directory')} id={`${id}-heading`}>
      <form
        aria-label={t('accounts.filter')}
        noValidate
        onSubmit={applyFilters}
        className="grid min-w-0 gap-4 sm:grid-cols-[minmax(0,1fr)_8rem_auto] sm:items-end"
      >
        <div className="min-w-0 space-y-2">
          <Label htmlFor={`${id}-status`}>{t('accounts.accountStatus')}</Label>
          <select
            id={`${id}-status`}
            value={accountStatus}
            className={querySelectClass}
            onChange={(event) => {
              discardResult();
              setAccountStatus(event.target.value as AdminUserStatus | '');
            }}
          >
            <option value="">{t('accounts.allStatuses')}</option>
            {accountStatuses.map((value) => (
              <option key={value} value={value}>
                {t(`statuses.${value}`)}
              </option>
            ))}
          </select>
        </div>
        <div className="min-w-0 space-y-2">
          <Label htmlFor={`${id}-size`}>{t('accounts.pageSize')}</Label>
          <Input
            ref={sizeInput}
            id={`${id}-size`}
            type="number"
            dir="ltr"
            min={1}
            max={limits.page_size_max}
            step={1}
            value={size}
            className={inputClass}
            aria-invalid={Boolean(sizeError)}
            aria-describedby={`${id}-size-help${sizeError ? ` ${id}-size-error` : ''}`}
            onChange={(event) => {
              discardResult();
              setSize(event.target.value);
              setSizeError('');
            }}
          />
        </div>
        <Button type="submit" className={controlClass} disabled={pending}>
          {t('accounts.apply')}
        </Button>
      </form>
      <p id={`${id}-size-help`} className="text-sm text-muted-foreground">
        {t('accounts.sizeHelp', { maximum: limits.page_size_max })}
      </p>
      {sizeError && (
        <p id={`${id}-size-error`} role="alert" className="text-sm text-red-700 dark:text-red-400">
          {message(sizeError)}
        </p>
      )}
      {!canPII && <p className="text-sm text-muted-foreground">{t('accounts.safeMetadata')}</p>}
      {canLookup && (
        <form
          method="post"
          autoComplete="off"
          aria-label={t('accounts.lookup')}
          noValidate
          onSubmit={lookup}
          className="space-y-3 border-t pt-4"
        >
          <div className="grid min-w-0 gap-3 sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-end">
            <div className="min-w-0 space-y-2">
              <Label htmlFor={`${id}-email`}>{t('accounts.email')}</Label>
              <Input
                ref={emailInput}
                id={`${id}-email`}
                type="email"
                dir="ltr"
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                maxLength={254}
                value={email}
                className={inputClass}
                aria-invalid={Boolean(emailError)}
                aria-describedby={`${id}-email-help${emailError ? ` ${id}-email-error` : ''}`}
                onChange={(event) => {
                  discardResult();
                  setEmail(event.target.value);
                  setEmailError('');
                }}
              />
            </div>
            <Button type="submit" className={controlClass} disabled={pending}>
              {t('accounts.find')}
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={() => {
                discardResult();
                setEmail('');
                setEmailError('');
                setStatus({ key: 'admin.accounts.lookupCleared' });
                emailInput.current?.focus();
              }}
            >
              {t('accounts.clear')}
            </Button>
          </div>
          <p id={`${id}-email-help`} className="text-sm text-muted-foreground">
            {t('accounts.emailHelp')}
          </p>
          {emailError && (
            <p
              id={`${id}-email-error`}
              role="alert"
              className="text-sm text-red-700 dark:text-red-400"
            >
              {message(emailError)}
            </p>
          )}
        </form>
      )}
      <Feedback error={error} status={status} />
      {pending && (
        <Button
          type="button"
          variant="outline"
          className={controlClass}
          onClick={() => {
            discardResult();
            setStatus({ key: 'admin.accounts.cancelled' });
          }}
        >
          {t('accounts.cancel')}
        </Button>
      )}
      {page && page.items.length > 0 && (
        <div
          role="region"
          aria-label={t('accounts.resultsRegion')}
          tabIndex={0}
          className={queryTableFrameClass}
          onFocus={revealQueryFocus}
        >
          <table className="w-full min-w-[26rem] border-collapse">
            <caption className="sr-only">
              {t(mode === 'lookup' ? 'accounts.lookupResult' : 'accounts.results')}
            </caption>
            <thead className="border-b bg-muted/40">
              <tr>
                <th scope="col" className={queryHeadClass}>
                  {t('accounts.reference')}
                </th>
                <th scope="col" className={queryHeadClass}>
                  {t('accounts.status')}
                </th>
                {canPII && (
                  <th scope="col" className={queryHeadClass}>
                    {t('accounts.emailColumn')}
                  </th>
                )}
                <th scope="col" className={`${queryHeadClass} hidden sm:table-cell`}>
                  {t('accounts.created')}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {page.items.map((account) => (
                <tr key={account.id} data-testid="admin-account-row">
                  <th scope="row" className={`${queryCellClass} max-w-64 font-normal`}>
                    <Link
                      href={`/admin/users/${account.id}`}
                      prefetch={false}
                      onClick={clearSensitiveViews}
                      aria-label={t('accounts.view', { id: account.id })}
                      className={`${linkClass} max-w-40 break-all font-mono text-xs sm:max-w-none`}
                    >
                      <bdi dir="ltr">{account.id}</bdi>
                    </Link>
                  </th>
                  <td className={queryCellClass}>
                    <span className="inline-block rounded border px-2 py-1 text-xs font-medium">
                      {t(`statuses.${account.status}`)}
                    </span>
                  </td>
                  {canPII && (
                    <td className={`${queryCellClass} max-w-64 break-all`}>
                      {account.email === undefined ? (
                        t('accounts.notProvided')
                      ) : (
                        <bdi dir="ltr">{account.email}</bdi>
                      )}
                    </td>
                  )}
                  <td className={`${queryCellClass} hidden sm:table-cell`}>
                    <QueryUtcTime value={account.created_at} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {page?.items.length === 0 && (
        <p className="text-sm">{t(mode === 'lookup' ? 'accounts.noMatch' : 'accounts.empty')}</p>
      )}
      {page && query && mode === 'list' && (
        <nav aria-label={t('accounts.pagination')} className="flex flex-wrap items-center gap-3">
          <Button
            type="button"
            variant="outline"
            className={controlClass}
            disabled={pending || page.offset === 0}
            onClick={() => void load({ ...query, offset: Math.max(0, page.offset - page.limit) })}
          >
            {t('accounts.previous')}
          </Button>
          <p className="min-w-0 text-sm text-muted-foreground">
            {t(page.items.length ? 'accounts.range' : 'accounts.emptyRange', {
              start: page.offset + 1,
              end: page.offset + page.items.length,
              total: page.total,
            })}
          </p>
          <Button
            type="button"
            variant="outline"
            className={controlClass}
            disabled={
              pending ||
              page.offset + page.limit >= page.total ||
              page.offset + page.limit > maxAccountOffset
            }
            onClick={() => void load({ ...query, offset: page.offset + page.limit })}
          >
            {t('accounts.next')}
          </Button>
          {page.offset + page.limit > maxAccountOffset && page.total > page.offset + page.limit && (
            <p className="text-sm">{t('accounts.offsetLimit')}</p>
          )}
        </nav>
      )}
    </Panel>
  );
}
