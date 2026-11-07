'use client';

import { Button, Input, Label } from '@hatef/ui';
import Link from 'next/link';
import { useId, useRef, useState, type FormEvent } from 'react';
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

const accountStatuses: Record<AdminUserStatus, string> = {
  active: 'Active',
  suspended: 'Suspended',
  banned: 'Banned',
  pending_verification: 'Pending verification',
  pending_deletion: 'Pending deletion',
};
const maxAccountOffset = 2147483647;

export function UsersView() {
  const { client, profile, capabilities, reportPermissionLoss } = usePortal();
  return (
    <>
      <PageHeading title="Accounts">
        Read bounded account pages and review individual accounts. Each disclosure is audited.
      </PageHeading>
      {capabilities?.capabilities.users_read ? (
        <AccountQuery
          key={`${profile.session.id}:${capabilities.capabilities.users_pii}:${capabilities.capabilities.users_lookup}`}
          client={client}
          capabilities={capabilities}
          reportPermissionLoss={reportPermissionLoss}
        />
      ) : (
        <Feedback error="This workspace does not grant account-read access. No accounts were requested." />
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
  const { limits } = capabilities;
  const canPII = capabilities.capabilities.users_pii;
  const canLookup = canPII && capabilities.capabilities.users_lookup;
  const [accountStatus, setAccountStatus] = useState<AdminUserStatus | ''>('');
  const [size, setSize] = useState(String(limits.page_size_default));
  const [email, setEmail] = useState('');
  const [page, setPage] = useState<(AdminUsersPage & { canonical_email?: string }) | null>(null);
  const [query, setQuery] = useState<AdminUsersQuery | null>(null);
  const [mode, setMode] = useState<'list' | 'lookup' | null>(null);
  const [pending, setPending] = useState(false);
  const [status, setStatus] = useState('Apply filters to load a bounded account page.');
  const [error, setError] = useState('');
  const [sizeError, setSizeError] = useState('');
  const [emailError, setEmailError] = useState('');
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
    setStatus('Inputs changed. Submit an explicit query to load results.');
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
    setStatus(lookup ? 'Looking up the exact email...' : 'Loading accounts...');
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
      setStatus(
        `${result.items.length} ${lookup ? 'matching accounts' : 'accounts on this page'} loaded.`
      );
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
      setSizeError(`Enter a whole page size from 1 to ${limits.page_size_max}.`);
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
    const value = email.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '');
    if (
      !/^[^@\s]+@[^@\s]+$/.test(value) ||
      /[\p{Cc}\p{Cs}\p{Default_Ignorable_Code_Point}\ufffd]/u.test(value) ||
      new TextEncoder().encode(email).length > 1024
    ) {
      setEmailError(
        'Enter one complete email address. The canonical address must fit 254 UTF-8 bytes.'
      );
      emailInput.current?.focus();
      return;
    }
    setEmailError('');
    void load(email);
  }

  if (cleared) return <Feedback status={queryClearedMessage} />;

  return (
    <Panel title="Account directory" id={`${id}-heading`}>
      <form
        aria-label="Filter accounts"
        noValidate
        onSubmit={applyFilters}
        className="grid min-w-0 gap-4 sm:grid-cols-[minmax(0,1fr)_8rem_auto] sm:items-end"
      >
        <div className="min-w-0 space-y-2">
          <Label htmlFor={`${id}-status`}>Account status</Label>
          <select
            id={`${id}-status`}
            value={accountStatus}
            className={querySelectClass}
            onChange={(event) => {
              discardResult();
              setAccountStatus(event.target.value as AdminUserStatus | '');
            }}
          >
            <option value="">All statuses</option>
            {Object.entries(accountStatuses).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <div className="min-w-0 space-y-2">
          <Label htmlFor={`${id}-size`}>Page size</Label>
          <Input
            ref={sizeInput}
            id={`${id}-size`}
            type="number"
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
          Apply filters
        </Button>
      </form>
      <p id={`${id}-size-help`} className="text-sm text-muted-foreground">
        Up to {limits.page_size_max} accounts per page. Only the current page is retained in memory.
      </p>
      {sizeError && (
        <p id={`${id}-size-error`} role="alert" className="text-sm text-red-700 dark:text-red-400">
          {sizeError}
        </p>
      )}
      {!canPII && (
        <p className="text-sm text-muted-foreground">
          This workspace lists safe account metadata only.
        </p>
      )}
      {canLookup && (
        <form
          method="post"
          autoComplete="off"
          aria-label="Exact email lookup"
          noValidate
          onSubmit={lookup}
          className="space-y-3 border-t pt-4"
        >
          <div className="grid min-w-0 gap-3 sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-end">
            <div className="min-w-0 space-y-2">
              <Label htmlFor={`${id}-email`}>Exact email</Label>
              <Input
                ref={emailInput}
                id={`${id}-email`}
                type="text"
                inputMode="email"
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
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
              Find account
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={() => {
                discardResult();
                setEmail('');
                setEmailError('');
                setStatus('Lookup query and result cleared.');
                emailInput.current?.focus();
              }}
            >
              Clear lookup
            </Button>
          </div>
          <p id={`${id}-email-help`} className="text-sm text-muted-foreground">
            Explicit exact matching only. The address is sent in the request body, never in the URL;
            no search runs while typing.
          </p>
          {emailError && (
            <p
              id={`${id}-email-error`}
              role="alert"
              className="text-sm text-red-700 dark:text-red-400"
            >
              {emailError}
            </p>
          )}
        </form>
      )}
      <Feedback error={error} status={status} />
      {page?.canonical_email && mode === 'lookup' && (
        <p className="break-all text-sm text-muted-foreground">
          Canonical email: <bdi>{page.canonical_email}</bdi>
        </p>
      )}
      {pending && (
        <Button
          type="button"
          variant="outline"
          className={controlClass}
          onClick={() => {
            discardResult();
            setStatus('Account request cancelled. No result was accepted.');
          }}
        >
          Cancel account request
        </Button>
      )}
      {page && page.items.length > 0 && (
        <div
          role="region"
          aria-label="Account results, horizontally scrollable"
          tabIndex={0}
          className={queryTableFrameClass}
          onFocus={revealQueryFocus}
        >
          <table className="w-full min-w-[26rem] border-collapse">
            <caption className="sr-only">
              {mode === 'lookup' ? 'Exact email lookup result' : 'Account results'}
            </caption>
            <thead className="border-b bg-muted/40">
              <tr>
                <th scope="col" className={queryHeadClass}>
                  Account reference
                </th>
                <th scope="col" className={queryHeadClass}>
                  Status
                </th>
                {canPII && (
                  <th scope="col" className={queryHeadClass}>
                    Email
                  </th>
                )}
                <th scope="col" className={`${queryHeadClass} hidden sm:table-cell`}>
                  Created (UTC)
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
                      aria-label={`View account ${account.id}`}
                      className={`${linkClass} max-w-40 break-all font-mono text-xs sm:max-w-none`}
                    >
                      {account.id}
                    </Link>
                  </th>
                  <td className={queryCellClass}>
                    <span className="inline-block rounded border px-2 py-1 text-xs font-medium">
                      {accountStatuses[account.status]}
                    </span>
                  </td>
                  {canPII && (
                    <td className={`${queryCellClass} max-w-64 break-all`}>
                      <bdi>{account.email ?? 'Not provided'}</bdi>
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
        <p className="text-sm">
          {mode === 'lookup'
            ? 'No account matched the exact email.'
            : 'No accounts returned on this page for the selected status.'}
        </p>
      )}
      {page && query && mode === 'list' && (
        <nav aria-label="Account pagination" className="flex flex-wrap items-center gap-3">
          <Button
            type="button"
            variant="outline"
            className={controlClass}
            disabled={pending || page.offset === 0}
            onClick={() => void load({ ...query, offset: Math.max(0, page.offset - page.limit) })}
          >
            Previous page
          </Button>
          <p className="min-w-0 text-sm text-muted-foreground">
            {page.items.length ? `${page.offset + 1}-${page.offset + page.items.length}` : '0'} of{' '}
            {page.total} matching accounts
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
            Next page
          </Button>
          {page.offset + page.limit > maxAccountOffset && page.total > page.offset + page.limit && (
            <p className="text-sm">
              The offset limit has been reached. Narrow the status filter or use an authorized exact
              lookup.
            </p>
          )}
        </nav>
      )}
    </Panel>
  );
}
