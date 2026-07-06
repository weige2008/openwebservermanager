import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  useReactTable,
  type Column,
  type ColumnDef,
  type PaginationState,
  type Row,
  type RowSelectionState,
  type VisibilityState,
} from '@tanstack/react-table'
import { Check, ChevronLeft, ChevronRight, Columns3, SearchIcon, X } from 'lucide-react'
import type { ReactNode } from 'react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Menu as BaseMenu } from '@base-ui/react/menu'

import {
  CardStaggerContainer,
  CardStaggerItem,
  TableStaggerContainer,
  TableStaggerRow,
} from '@/components/page-transition'
import { cn } from '@/lib/utils'

import { Button } from '../ui/button'
import { EmptyState } from '../ui/empty-state'
import { Input, Select } from '../ui/field'

export function DataTable<TData>({
  columns,
  data,
  emptyTitle,
  emptyBody,
  className,
  searchPlaceholder,
  getSearchText,
  getRowID,
  selection,
}: {
  columns: ColumnDef<TData>[]
  data: TData[]
  emptyTitle: string
  emptyBody: string
  className?: string
  searchPlaceholder?: string
  getSearchText?: (row: TData) => string
  getRowID?: (row: TData) => string
  selection?: {
    selectedIDs: string[]
    onSelectedIDsChange: (selectedIDs: string[]) => void
    actions?: ReactNode
  }
}) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({})
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 20 })
  const normalizedQuery = query.trim().toLowerCase()
  const stableColumns = useMemo(() => withStableColumnIDs(columns), [columns])
  const selectionColumn = useMemo<ColumnDef<TData> | null>(() => {
    if (!selection || !getRowID) return null
    return {
      id: '__select',
      enableHiding: false,
      header: ({ table }) => (
        <SelectionCheckbox
          ariaLabel={t('selectAllRows')}
          checked={table.getIsAllPageRowsSelected()}
          indeterminate={table.getIsSomePageRowsSelected()}
          onChange={(checked) => table.toggleAllPageRowsSelected(checked)}
        />
      ),
      cell: ({ row }) => (
        <SelectionCheckbox
          ariaLabel={t('selectRow')}
          checked={row.getIsSelected()}
          disabled={!row.getCanSelect()}
          onChange={(checked) => row.toggleSelected(checked)}
        />
      ),
    }
  }, [getRowID, selection, t])
  const tableColumns = useMemo(() => selectionColumn ? [selectionColumn, ...stableColumns] : stableColumns, [selectionColumn, stableColumns])
  const filteredData = useMemo(() => {
    if (!normalizedQuery || !getSearchText) return data
    return data.filter((row) => getSearchText(row).toLowerCase().includes(normalizedQuery))
  }, [data, getSearchText, normalizedQuery])
  const rowSelection = useMemo<RowSelectionState>(() => {
    if (!selection) return {}
    return Object.fromEntries(selection.selectedIDs.map((id) => [id, true]))
  }, [selection])

  const table = useReactTable({
    data: filteredData,
    columns: tableColumns,
    getRowId: getRowID,
    enableRowSelection: Boolean(selection && getRowID),
    state: {
      columnVisibility,
      pagination,
      rowSelection,
    },
    onColumnVisibilityChange: setColumnVisibility,
    onPaginationChange: setPagination,
    onRowSelectionChange: selection
      ? (updater) => {
        const previous = Object.fromEntries(selection.selectedIDs.map((id) => [id, true]))
        const next = typeof updater === 'function' ? updater(previous) : updater
        selection.onSelectedIDsChange(Object.keys(next).filter((id) => next[id]))
      }
      : undefined,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  })
  const totalPages = Math.max(table.getPageCount(), 1)
  const visibleLeafColumns = table.getAllLeafColumns().filter((column) => column.getCanHide())

  useEffect(() => {
    setPagination((current) => ({ ...current, pageIndex: 0 }))
  }, [normalizedQuery, data.length])

  if (!data.length) {
    return (
      <div data-slot='table-empty' className={cn('rounded-xl ring-1 ring-foreground/10', className)}>
        <EmptyState title={emptyTitle} body={emptyBody} />
      </div>
    )
  }

  return (
    <div className={cn('grid min-w-0 gap-2.5 sm:gap-3', className)}>
      <div className='flex flex-wrap items-center gap-2 sm:gap-3'>
        {getSearchText ? (
          <div className='relative w-full sm:w-[240px]'>
            <SearchIcon className='pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground' />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={searchPlaceholder || t('filter')}
              className='pl-8'
            />
          </div>
        ) : null}
        {query ? (
          <Button variant='ghost' size='sm' className='text-muted-foreground' onClick={() => setQuery('')}>
            {t('resetFilter')}
            <X className='size-3.5' />
          </Button>
        ) : null}
        <div className='ms-auto flex flex-wrap items-center justify-end gap-2 text-xs text-muted-foreground'>
          <span>{filteredData.length} / {data.length}</span>
          <ColumnVisibilityMenu columns={visibleLeafColumns} />
        </div>
      </div>
      {selection && selection.selectedIDs.length ? (
        <div className='flex flex-wrap items-center justify-between gap-2 rounded-xl border border-primary/20 bg-primary/5 px-3 py-2 text-sm'>
          <span className='font-medium text-primary'>
            {t('selectedRows', { defaultValue: '{{count}} selected', count: selection.selectedIDs.length })}
          </span>
          <div className='flex flex-wrap items-center justify-end gap-2'>
            {selection.actions}
            <Button variant='ghost' size='sm' onClick={() => selection.onSelectedIDsChange([])}>
              {t('clearSelection')}
            </Button>
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
      <TablePagination
        pageIndex={pagination.pageIndex}
        pageSize={pagination.pageSize}
        totalPages={totalPages}
        totalRows={filteredData.length}
        canPreviousPage={table.getCanPreviousPage()}
        canNextPage={table.getCanNextPage()}
        onPrevious={() => table.previousPage()}
        onNext={() => table.nextPage()}
        onPageSizeChange={(pageSize) => table.setPageSize(pageSize)}
      />
      </>
      )}
    </div>
  )
}

function withStableColumnIDs<TData>(columns: ColumnDef<TData>[]): ColumnDef<TData>[] {
  return columns.map((column, index) => {
    const header = typeof column.header === 'string' || typeof column.header === 'number' ? String(column.header) : ''
    const base = header || `column-${index + 1}`
    const id = column.id || stableColumnID(base, index)
    return {
      ...column,
      id,
      enableHiding: id === 'actions' || id === '__select' ? false : column.enableHiding,
    }
  })
}

function stableColumnID(value: string, index: number) {
  const normalized = value.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^\p{L}\p{N}_-]+/gu, '')
  return normalized || `column-${index + 1}`
}

function ColumnVisibilityMenu<TData>({ columns }: { columns: Column<TData, unknown>[] }) {
  const { t } = useTranslation()
  const visibleCount = columns.filter((column) => column.getIsVisible()).length
  if (!columns.length) return null
  return (
    <BaseMenu.Root>
      <BaseMenu.Trigger
        className='inline-flex h-8 items-center gap-2 rounded-lg border border-input bg-background px-2.5 text-sm font-medium text-foreground shadow-xs transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-ring/50'
      >
        <Columns3 className='size-4' />
        {t('columns')}
      </BaseMenu.Trigger>
      <BaseMenu.Portal>
        <BaseMenu.Positioner sideOffset={6} className='z-50'>
          <BaseMenu.Popup className='min-w-48 rounded-xl border border-border bg-popover p-1 text-popover-foreground shadow-lg outline-none'>
            <BaseMenu.Item
              className='flex h-8 cursor-default items-center gap-2 rounded-lg px-2 text-sm outline-none transition-colors data-[highlighted]:bg-muted'
              onClick={() => columns.forEach((column) => column.toggleVisibility(true))}
            >
              <Check className='size-3.5 opacity-0' />
              {t('showAllColumns')}
            </BaseMenu.Item>
            <div className='my-1 h-px bg-border' />
            {columns.map((column) => (
              <BaseMenu.CheckboxItem
                key={column.id}
                checked={column.getIsVisible()}
                disabled={column.getIsVisible() && visibleCount <= 1}
                onCheckedChange={(checked) => column.toggleVisibility(checked)}
                className='flex h-8 cursor-default items-center gap-2 rounded-lg px-2 text-sm outline-none transition-colors data-[disabled]:opacity-50 data-[highlighted]:bg-muted'
              >
                <Check className={cn('size-3.5', column.getIsVisible() ? 'opacity-100' : 'opacity-0')} />
                <span className='truncate'>{renderHeader(column.columnDef.header, column.id)}</span>
              </BaseMenu.CheckboxItem>
            ))}
          </BaseMenu.Popup>
        </BaseMenu.Positioner>
      </BaseMenu.Portal>
    </BaseMenu.Root>
  )
}

function TablePagination({
  pageIndex,
  pageSize,
  totalPages,
  totalRows,
  canPreviousPage,
  canNextPage,
  onPrevious,
  onNext,
  onPageSizeChange,
}: {
  pageIndex: number
  pageSize: number
  totalPages: number
  totalRows: number
  canPreviousPage: boolean
  canNextPage: boolean
  onPrevious: () => void
  onNext: () => void
  onPageSizeChange: (pageSize: number) => void
}) {
  const { t } = useTranslation()
  const firstRow = totalRows === 0 ? 0 : pageIndex * pageSize + 1
  const lastRow = Math.min(totalRows, (pageIndex + 1) * pageSize)

  return (
    <div className='flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground'>
      <div>
        {t('paginationRange', {
          defaultValue: '{{first}}-{{last}} of {{total}}',
          first: firstRow,
          last: lastRow,
          total: totalRows,
        })}
      </div>
      <div className='flex items-center gap-2'>
        <span>{t('rowsPerPage')}</span>
        <Select className='h-8 w-20 text-xs' value={String(pageSize)} onChange={(event) => onPageSizeChange(Number(event.currentTarget.value))}>
          {[10, 20, 50, 100].map((size) => (
            <option key={size} value={size}>{size}</option>
          ))}
        </Select>
        <span>{t('paginationPage', { defaultValue: 'Page {{page}} / {{total}}', page: pageIndex + 1, total: totalPages })}</span>
        <Button size='icon-sm' variant='outline' onClick={onPrevious} disabled={!canPreviousPage} aria-label={t('previousPage')}>
          <ChevronLeft className='size-4' />
        </Button>
        <Button size='icon-sm' variant='outline' onClick={onNext} disabled={!canNextPage} aria-label={t('nextPage')}>
          <ChevronRight className='size-4' />
        </Button>
      </div>
    </div>
  )
}

function MobileRowCard<TData>({ row }: { row: Row<TData> }) {
  const allCells = row.getVisibleCells()
  const selectCell = allCells.find((cell) => cell.column.id === '__select')
  const actionsCell = allCells.find((cell) => cell.column.id === 'actions')
  const visibleCells = allCells.filter((cell) => cell.column.id !== '__select' && cell.column.id !== 'actions')
  const [primaryCell, ...detailCells] = visibleCells

  return (
    <article data-slot='mobile-row-card' className='rounded-xl bg-card p-3 text-sm ring-1 ring-foreground/10'>
      <div className='flex min-w-0 items-start justify-between gap-3'>
        <div className='flex min-w-0 items-start gap-2'>
          {selectCell ? (
            <div className='pt-0.5'>{flexRender(selectCell.column.columnDef.cell, selectCell.getContext())}</div>
          ) : null}
          <div className='min-w-0 font-medium'>{primaryCell ? flexRender(primaryCell.column.columnDef.cell, primaryCell.getContext()) : null}</div>
        </div>
        {actionsCell ? (
          <div className='shrink-0'>{flexRender(actionsCell.column.columnDef.cell, actionsCell.getContext())}</div>
        ) : null}
      </div>
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

function SelectionCheckbox({
  checked,
  indeterminate,
  disabled,
  ariaLabel,
  onChange,
}: {
  checked: boolean
  indeterminate?: boolean
  disabled?: boolean
  ariaLabel: string
  onChange: (checked: boolean) => void
}) {
  const ref = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (ref.current) ref.current.indeterminate = Boolean(indeterminate)
  }, [indeterminate])

  return (
    <input
      ref={ref}
      type='checkbox'
      className='size-4 rounded border-border accent-primary'
      checked={checked}
      disabled={disabled}
      aria-label={ariaLabel}
      onClick={(event) => event.stopPropagation()}
      onChange={(event) => onChange(event.currentTarget.checked)}
    />
  )
}
