'use client';

import { Button, cn } from '@hatef/ui';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { controlClass } from '../../_components/controls';
import {
  queryCellClass,
  queryHeadClass,
  queryTableFrameClass,
  revealQueryFocus,
} from './query-view-state';

type ResultColumn = {
  id: string;
  label: string;
  rowHeader?: boolean;
  wide?: boolean;
  secondary?: boolean;
};
type ResultRow = { id: string; testId: string; cells: ReactNode[] };
const widths = {
  26: ['min-w-[26rem]', 'lg:min-w-[26rem]'],
  36: ['min-w-[36rem]', 'lg:min-w-[36rem]'],
  48: ['min-w-[48rem]', 'lg:min-w-[48rem]'],
  54: ['min-w-[54rem]', 'lg:min-w-[54rem]'],
} as const;

// One result/control tree keeps targets and modal openers intact during layout changes.
// Explicit table roles retain its semantics when compact rows use a CSS grid.
export function AdminResults({
  label,
  caption,
  viewLabel,
  compactLabel,
  tableLabel,
  columns,
  rows,
  width,
  privateRegion = false,
}: {
  label: string;
  caption: string;
  viewLabel: string;
  compactLabel: string;
  tableLabel: string;
  columns: ResultColumn[];
  rows: ResultRow[];
  width: keyof typeof widths;
  privateRegion?: boolean;
}) {
  const [table, setTable] = useState(false);
  const [desktop, setDesktop] = useState(false);
  const controls = useRef<HTMLDivElement>(null);
  const frame = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!window.matchMedia) return;
    const media = window.matchMedia('(min-width: 1024px)');
    function changed() {
      if (media.matches && controls.current?.contains(document.activeElement)) {
        frame.current?.focus();
      }
      setDesktop(media.matches);
    }
    changed();
    media.addEventListener('change', changed);
    return () => media.removeEventListener('change', changed);
  }, []);
  const compact = !desktop && !table;

  return (
    <div className="min-w-0 space-y-3" data-result-view={compact ? 'compact' : 'table'}>
      <div
        ref={controls}
        role="group"
        aria-label={viewLabel}
        hidden={desktop}
        className="flex flex-wrap gap-2 lg:hidden"
      >
        <Button
          type="button"
          variant={table ? 'outline' : 'default'}
          className={controlClass}
          aria-pressed={!table}
          onClick={() => setTable(false)}
        >
          {compactLabel}
        </Button>
        <Button
          type="button"
          variant={table ? 'default' : 'outline'}
          className={controlClass}
          aria-pressed={table}
          onClick={() => setTable(true)}
        >
          {tableLabel}
        </Button>
      </div>
      <div
        ref={frame}
        role="region"
        aria-label={label}
        tabIndex={0}
        data-legal-private={privateRegion || undefined}
        className={cn(queryTableFrameClass, compact && 'overflow-x-visible lg:overflow-x-auto')}
        onFocus={revealQueryFocus}
      >
        <table
          role="table"
          className={cn('w-full border-collapse', !compact
            ? widths[width][0] : ['block min-w-0 lg:table', widths[width][1]])}
        >
          <caption className="sr-only">{caption}</caption>
          <thead
            role="rowgroup"
            className={cn('border-b bg-muted/40', compact && 'sr-only lg:not-sr-only lg:table-header-group')}
          >
            <tr role="row">
              {columns.map((column) => (
                <th key={column.id} role="columnheader" scope="col" className={queryHeadClass}>
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody role="rowgroup" className={cn('divide-y', compact && 'block lg:table-row-group')}>
            {rows.map((row) => (
              <tr
                key={row.id}
                role="row"
                data-testid={row.testId}
                data-result-id={row.id}
                className={compact ? 'grid grid-cols-1 gap-3 p-4 sm:grid-cols-2 lg:table-row lg:p-0' : undefined}
              >
                {columns.map((column, index) => {
                  const Cell = column.rowHeader ? 'th' : 'td';
                  return (
                    <Cell
                      key={column.id}
                      role={column.rowHeader ? 'rowheader' : 'cell'}
                      scope={column.rowHeader ? 'row' : undefined}
                      className={cn(
                        queryCellClass,
                        'min-w-0 break-words',
                        column.rowHeader && 'font-medium',
                        compact && 'block px-0 py-0 lg:table-cell lg:px-3 lg:py-2',
                        compact && column.wide && 'col-span-full',
                        compact && column.secondary && 'order-1 lg:order-none'
                      )}
                    >
                      <span
                        aria-hidden="true"
                        className={!compact ? 'hidden' : 'mb-1 block text-xs font-normal text-muted-foreground lg:hidden'}
                      >
                        {column.label}
                      </span>
                      {row.cells[index]}
                    </Cell>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
