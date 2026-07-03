import type { ColumnDef } from '@tanstack/react-table'
import { Plus } from 'lucide-react'
import { useMemo } from 'react'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { credentialLabel, formatDate } from '@/lib/utils'
import type { Credential } from '@/types'

export function CredentialsPage() {
  const app = useApp()
  const columns = useMemo<ColumnDef<Credential>[]>(
    () => [
      { header: '名称', cell: ({ row }) => <strong>{row.original.name}</strong> },
      { header: '类型', cell: ({ row }) => <Badge>{credentialLabel(row.original.type)}</Badge> },
      { header: '用户名', accessorFn: (row) => row.username },
      { header: '域 / 工作组', accessorFn: (row) => row.domain || '-' },
      { header: '创建时间', cell: ({ row }) => formatDate(row.original.created_at) },
    ],
    []
  )

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>凭据库</CardTitle>
          <CardDescription>敏感字段加密保存在服务端，API 响应不会返回明文。</CardDescription>
        </div>
        <Button variant='primary' onClick={() => app.setModal({ type: 'credential' })}>
          <Plus className='size-4' />
          添加凭据
        </Button>
      </CardHeader>
      <DataTable
        columns={columns}
        data={app.data.credentials}
        emptyTitle='还没有凭据'
        emptyBody='添加 SSH 或 RDP 凭据后才能发起连接。'
        searchPlaceholder='过滤凭据...'
        getSearchText={(credential) => [credential.name, credential.type, credential.username, credential.domain].filter(Boolean).join(' ')}
      />
    </Card>
  )
}
