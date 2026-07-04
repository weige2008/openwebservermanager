import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type Row,
} from '@tanstack/react-table'
import { SearchIcon, X } from 'lucide-react'
import type { ReactNode } from 'react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import {
  CardStaggerContainer,
  CardStaggerItem,
  TableStaggerContainer,
  TableStaggerRow,
} from '@/components/page-transition'
import { cn } from '@/lib/utils'

import { Button } from '../ui/button'
import { EmptyState } from '../ui/empty-state'
import { Input } from '../ui/field'

export function DataTable<TData>({
  columns,
  data,
  emptyTitle,
  emptyBody,
  className,
  searchPlaceholder,
  getSearchText,
}: {
  columns: ColumnDef<TData>[]
  data: TData[]
  emptyTitle: string
  emptyBody: string
  className?: string
  searchPlaceholder?: string
  getSearchText?: (row: TData) => string
}) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const normalizedQuery = query.trim().toLowerCase()
  const filteredData = useMemo(() => {
    if (!normalizedQuery || !getSearchText) return data
    return data.filter((row) => getSearchText(row).toLowerCase().includes(normalizedQuery))
  }, [data, getSearchText, normalizedQuery])

  const table = useReactTable({
    data: filteredData,
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
    <div className={cn('grid min-w-0 gap-2.5 sm:gap-3', className)}>
      {getSearchText ? (
        <div className='flex flex-wrap items-center gap-2 sm:gap-3'>
          <div className='relative w-full sm:w-[240px]'>
            <SearchIcon className='pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground' />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={searchPlaceholder || t('filter')}
              className='pl-8'
            />
          </div>
          {query ? (
            <Button variant='ghost' size='sm' className='text-muted-foreground' onClick={() => setQuery('')}>
              {t('resetFilter')}
              <X className='size-3.5' />
            </Button>
          ) : null}
          <div className='ms-auto text-xs text-muted-foreground'>
            {filteredData.length} / {data.length}
          </div>
        </div>
      ) : null}
      {!filteredData.length ? (
        <div data-slot='table-empty' className='rounded-xl ring-1 ring-foreground/10'>
          <EmptyState title={t('noMatches')} body={t('noMatchesBody')} />
        </div>
      ) : (
      <>
      <CardStaggerContainer className='grid gap-3 sm:hidden'>
        {table.getRowModel().rows.map((row) => (
          <CardStaggerItem key={row.id}>
            <MobileRowCard row={row} />
          </CardStaggerItem>
        ))}
      </CardStaggerContainer>
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
        <TableStaggerContainer>
          {table.getRowModel().rows.map((row) => (
            <TableStaggerRow key={row.id} className='border-b border-border bg-table-row last:border-b-0 hover:bg-muted/50'>
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} className='h-10 max-w-[20rem] px-3 align-middle tabular-nums'>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </TableStaggerRow>
          ))}
        </TableStaggerContainer>
      </table>
      </div>
      </>
      )}
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
