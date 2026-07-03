import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type Row,
} from '@tanstack/react-table'
import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

import { EmptyState } from '../ui/empty-state'

export function DataTable<TData>({
  columns,
  data,
  emptyTitle,
  emptyBody,
  className,
}: {
  columns: ColumnDef<TData>[]
  data: TData[]
  emptyTitle: string
  emptyBody: string
  className?: string
}) {
  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
  })

  if (!data.length) {
    return (
      <div data-slot='table-empty' className={cn('rounded-xl ring-1 ring-foreground/10', className)}>
        <EmptyState title={emptyTitle} body={emptyBody} />
      </div>
    )
  }

  return (
    <div className={cn('min-w-0', className)}>
      <div className='grid gap-3 sm:hidden'>
        {table.getRowModel().rows.map((row) => (
          <MobileRowCard key={row.id} row={row} />
        ))}
      </div>
      <div data-slot='table-container' className='hidden overflow-auto rounded-xl ring-1 ring-foreground/10 sm:block'>
        <table data-slot='table' className='w-full border-collapse text-sm'>
        <thead>
          {table.getHeaderGroups().map((group) => (
            <tr key={group.id} className='border-b border-border bg-table-header text-left text-xs text-muted-foreground'>
              {group.headers.map((header) => (
                <th key={header.id} className='h-9 px-3 text-start align-middle font-medium'>
                  {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => (
            <tr key={row.id} className='border-b border-border bg-table-row last:border-b-0 hover:bg-muted/50'>
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} className='h-10 max-w-[20rem] px-3 align-middle tabular-nums'>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    </div>
  )
}

function MobileRowCard<TData>({ row }: { row: Row<TData> }) {
  const visibleCells = row.getVisibleCells()
  const [primaryCell, ...detailCells] = visibleCells

  return (
    <article data-slot='mobile-row-card' className='rounded-xl bg-card p-3 text-sm ring-1 ring-foreground/10'>
      <div className='min-w-0 font-medium'>{primaryCell ? flexRender(primaryCell.column.columnDef.cell, primaryCell.getContext()) : null}</div>
      <dl className='mt-3 grid gap-2'>
        {detailCells.map((cell) => (
          <div key={cell.id} className='grid grid-cols-[6rem_minmax(0,1fr)] gap-3 text-xs'>
            <dt className='truncate text-muted-foreground'>{renderHeader(cell.column.columnDef.header, cell.column.id)}</dt>
            <dd className='min-w-0 text-foreground'>{flexRender(cell.column.columnDef.cell, cell.getContext())}</dd>
          </div>
        ))}
      </dl>
    </article>
  )
}

function renderHeader<TData>(header: ColumnDef<TData>['header'], fallback: string): ReactNode {
  if (typeof header === 'string' || typeof header === 'number') return header
  return fallback
}
