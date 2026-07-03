import type { ColumnDef } from '@tanstack/react-table'
import { useMemo } from 'react'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { formatDate } from '@/lib/utils'
import type { AuditLog } from '@/types'

export function AuditPage() {
  const { data } = useApp()
  const columns = useMemo<ColumnDef<AuditLog>[]>(
    () => [
      { header: '时间', cell: ({ row }) => formatDate(row.original.created_at) },
      { header: '动作', cell: ({ row }) => <span className='font-mono text-xs'>{row.original.action}</span> },
      { header: '目标', accessorFn: (row) => row.target_id || '-' },
      { header: '协议', accessorFn: (row) => row.protocol || '-' },
      { header: '来源', accessorFn: (row) => row.client_ip || '-' },
      { header: '详情', accessorFn: (row) => row.detail || '' },
    ],
    []
  )

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>审计日志</CardTitle>
          <CardDescription>连接、断开、凭据创建、录屏访问都会记录。</CardDescription>
        </div>
      </CardHeader>
      <DataTable columns={columns} data={[...data.audit_logs].reverse()} emptyTitle='暂无审计日志' emptyBody='登录与连接操作会逐步写入这里。' />
    </Card>
  )
}
