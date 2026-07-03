import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'

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

  if (!data.length) return <EmptyState title={emptyTitle} body={emptyBody} />

  return (
    <div className={cn('overflow-auto', className)}>
      <table className='w-full border-collapse text-sm'>
        <thead>
          {table.getHeaderGroups().map((group) => (
            <tr key={group.id} className='bg-table-header text-left text-xs text-muted-foreground'>
              {group.headers.map((header) => (
                <th key={header.id} className='px-3 py-3 font-semibold'>
                  {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => (
            <tr key={row.id} className='border-b border-border last:border-b-0 hover:bg-accent/45'>
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} className='px-3 py-3 align-middle'>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
