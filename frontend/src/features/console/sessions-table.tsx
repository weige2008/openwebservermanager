import type { ColumnDef } from '@tanstack/react-table'
import { Download } from 'lucide-react'
import { useMemo } from 'react'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { apiRequest } from '@/lib/api'
import { formatDate, statusLabel } from '@/lib/utils'
import type { ConnectionSession } from '@/types'

export function SessionsTable({ sessions }: { sessions: ConnectionSession[] }) {
  const app = useApp()
  const serverName = (id: string) => app.data.servers.find((server) => server.id === id)?.name || id

  const closeSession = async (id: string) => {
    await apiRequest(`/api/connections/${id}/close`, { method: 'POST', body: '{}' })
    await app.refresh(true)
  }

  const columns = useMemo<ColumnDef<ConnectionSession>[]>(
    () => [
      {
        header: '协议',
        cell: ({ row }) => <Badge tone={row.original.protocol === 'rdp' ? 'info' : 'neutral'}>{row.original.protocol.toUpperCase()}</Badge>,
      },
      {
        header: '服务器',
        cell: ({ row }) => (
          <div>
            <strong>{serverName(row.original.server_id)}</strong>
            <div className='font-mono text-xs text-muted-foreground'>{row.original.id}</div>
          </div>
        ),
      },
      {
        header: '状态',
        cell: ({ row }) => (
          <Badge tone={row.original.status === 'active' ? 'success' : row.original.status === 'pending' ? 'warning' : row.original.status === 'failed' ? 'danger' : 'neutral'}>
            {statusLabel(row.original.status)}
          </Badge>
        ),
      },
      { header: '来源', accessorFn: (row) => row.client_ip || '-' },
      { header: '开始时间', cell: ({ row }) => formatDate(row.original.started_at) },
      { header: '录屏', cell: ({ row }) => (row.original.recording_path ? `${row.original.recording_size || 0} bytes` : '-') },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className='flex justify-end gap-2'>
            {row.original.recording_path ? (
              <Button size='sm' variant='outline' onClick={() => { window.location.href = `/api/connections/${row.original.id}/recording.zip` }}>
                <Download className='size-3.5' />
                下载录屏
              </Button>
            ) : null}
            <Button size='sm' variant='outline' onClick={() => void closeSession(row.original.id)}>关闭</Button>
          </div>
        ),
      },
    ],
    [app.data.servers]
  )

  return (
    <DataTable
      columns={columns}
      data={sessions}
      emptyTitle='暂无连接会话'
      emptyBody='从服务器列表发起 SSH 或 RDP 后会出现在这里。'
    />
  )
}
