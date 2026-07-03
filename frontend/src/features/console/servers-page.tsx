import type { ColumnDef } from '@tanstack/react-table'
import { Plus } from 'lucide-react'
import { useMemo } from 'react'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { osLabel } from '@/lib/utils'
import type { ManagedServer } from '@/types'

export function ServersPage() {
  const app = useApp()
  const columns = useMemo<ColumnDef<ManagedServer>[]>(
    () => [
      {
        header: '名称',
        cell: ({ row }) => (
          <div>
            <strong>{row.original.name}</strong>
            <div className='text-xs text-muted-foreground'>{row.original.description || '无描述'}</div>
          </div>
        ),
      },
      { header: '地址', cell: ({ row }) => <span className='font-mono text-xs'>{row.original.host}</span> },
      { header: '系统', cell: ({ row }) => <Badge tone={row.original.os === 'windows' ? 'info' : 'neutral'}>{osLabel(row.original.os)}</Badge> },
      { header: '端口', cell: ({ row }) => `SSH ${row.original.ssh_port || 22} / RDP ${row.original.rdp_port || 3389}` },
      { header: '分组', accessorFn: (row) => row.group || '-' },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className='flex justify-end gap-2'>
            <Button size='sm' variant='primary' onClick={() => app.setModal({ type: 'connect', protocol: 'ssh', serverId: row.original.id })}>SSH</Button>
            <Button size='sm' variant='outline' onClick={() => app.setModal({ type: 'connect', protocol: 'rdp', serverId: row.original.id })}>RDP</Button>
          </div>
        ),
      },
    ],
    [app]
  )

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>服务器资产</CardTitle>
          <CardDescription>登录后可见，连接动作会写入审计日志。</CardDescription>
        </div>
        <Button variant='primary' onClick={() => app.setModal({ type: 'server' })}>
          <Plus className='size-4' />
          添加服务器
        </Button>
      </CardHeader>
      <DataTable columns={columns} data={app.data.servers} emptyTitle='还没有服务器' emptyBody='添加服务器后，SSH/RDP 入口会出现在列表右侧。' />
    </Card>
  )
}
