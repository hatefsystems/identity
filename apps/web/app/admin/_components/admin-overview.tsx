'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';
import { PageHeading, linkClass } from '../../_components/controls';
import { usePortal } from '../../_components/portal-provider';
import { clearSensitiveViews } from '../../_lib/portal/invalidation';

export function AdminOverview() {
  const t = useTranslations('admin');
  const { capabilities } = usePortal();
  const access = capabilities?.capabilities;
  const workspaces = [
    ...(access?.users_read
      ? [
          {
            href: '/admin/users',
            title: t('overview.accounts'),
            description: t('overview.accountsDescription'),
          },
        ]
      : []),
    ...(access?.audit_logs_read
      ? [
          {
            href: '/admin/audit-logs',
            title: t('overview.audit'),
            description: t('overview.auditDescription'),
          },
        ]
      : []),
    ...(access?.audit_chain_verify || access?.ledger_verify
      ? [
          {
            href: '/admin/integrity',
            title: t('overview.integrity'),
            description: t('overview.integrityDescription'),
          },
        ]
      : []),
    ...(access?.legal_holds_read ||
    access?.legal_holds_apply ||
    access?.legal_holds_release ||
    access?.preservation_requests_create ||
    access?.legal_inquiry_lookup
      ? [
          {
            href: '/admin/legal',
            title: t('overview.legal'),
            description: t('overview.legalDescription'),
          },
        ]
      : []),
  ];
  return (
    <>
      <PageHeading title={t('overview.title')}>{t('overview.description')}</PageHeading>
      <section aria-labelledby="admin-workspaces" className="min-w-0 rounded-xl border bg-card">
        <h2 id="admin-workspaces" className="border-b px-5 py-4 font-semibold">
          {t('overview.workspaces')}
        </h2>
        <ul className="divide-y">
          {workspaces.map((workspace) => (
            <li
              key={workspace.href}
              className="grid gap-1 px-4 py-3 sm:grid-cols-[10rem_minmax(0,1fr)] sm:items-center"
            >
              <Link
                href={workspace.href}
                prefetch={false}
                onClick={clearSensitiveViews}
                className={linkClass}
              >
                {workspace.title}
              </Link>
              <p className="px-2 text-sm leading-relaxed text-muted-foreground">
                {workspace.description}
              </p>
            </li>
          ))}
        </ul>
      </section>
      <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
        {t('overview.clearing')}
      </p>
    </>
  );
}
