'use client';

import Link from 'next/link';
import { PageHeading, linkClass } from '../../_components/controls';
import { usePortal } from '../../_components/portal-provider';
import { clearSensitiveViews } from '../../_lib/portal/invalidation';

export function AdminOverview() {
  const { capabilities } = usePortal();
  const access = capabilities?.capabilities;
  const workspaces = [
    ...(access?.users_read
      ? [
          {
            href: '/admin/users',
            title: 'Accounts',
            description: 'Read permitted account metadata and review available status actions.',
          },
        ]
      : []),
    ...(access?.audit_logs_read
      ? [
          {
            href: '/admin/audit-logs',
            title: 'Audit logs',
            description: 'Search a bounded UTC window. Every disclosed page is audited.',
          },
        ]
      : []),
    ...(access?.audit_chain_verify || access?.ledger_verify
      ? [
          {
            href: '/admin/integrity',
            title: 'Integrity',
            description: 'Verify audit or security-ledger links in explicit, bounded pages.',
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
            title: 'DPO and Legal',
            description:
              'Manage independent Legal Holds, preservation requests, and bounded attribution inquiries.',
          },
        ]
      : []),
  ];
  return (
    <>
      <PageHeading title="Admin control panel">
        Elevated access is limited to your current permissions. Reads and actions are durably
        audited; access is checked again by the API on every operation.
      </PageHeading>
      <section aria-labelledby="admin-workspaces" className="min-w-0 rounded-xl border bg-card">
        <h2 id="admin-workspaces" className="border-b px-5 py-4 font-semibold">
          Available workspaces
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
        Private results and drafts are cleared when this page is backgrounded or left. Return to
        revalidate access. No operation, search, or verification continues automatically in the
        background.
      </p>
    </>
  );
}
