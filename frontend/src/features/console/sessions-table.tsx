import type { ColumnDef } from '@tanstack/react-table'
import { Download } from 'lucide-react'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { apiRequest } from '@/lib/api'
import { formatDate, statusLabel } from '@/lib/utils'
import type { ConnectionSession } from '@/types'

export function SessionsTable({ sessions }: { sessions: ConnectionSession[] }) {
  const app = useApp()
  const { t } = useTranslation()
  const serverName = (id: string) => app.data.servers.find((server) => server.id === id)?.name || id

  const closeSession = async (id: string) => {
    await apiRequest(`/api/connections/${id}/close`, { method: 'POST', body: '{}' })
    await app.refresh(true)
  }

  const columns = useMemo<ColumnDef<ConnectionSession>[]>(
    () => [
      {
        header: t('protocol'),
        cell: ({ row }) => <Badge tone={row.original.protocol === 'rdp' ? 'info' : 'neutral'}>{row.original.protocol.toUpperCase()}</Badge>,
      },
      {
        header: t('server'),
        cell: ({ row }) => (
          <div>
            <strong>{serverName(row.original.server_id)}</strong>
            <div className='font-mono text-xs text-muted-foreground'>{row.original.id}</div>
          </div>
        ),
      },
      {
        header: t('status'),
        cell: ({ row }) => (
          <Badge tone={row.original.status === 'active' ? 'success' : row.original.status === 'pending' ? 'warning' : row.original.status === 'failed' ? 'danger' : 'neutral'}>
            {statusLabel(row.original.status)}
          </Badge>
        ),
      },
      { header: t('source'), accessorFn: (row) => row.client_ip || '-' },
      { header: t('startedAt'), cell: ({ row }) => formatDate(row.original.started_at) },
      { header: t('recording'), cell: ({ row }) => (row.original.recording_path ? `${row.original.recording_size || 0} bytes` : '-') },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className='flex justify-end gap-2'>
            {row.original.recording_path ? (
              <Button size='sm' variant='outline' onClick={() => { window.location.href = `/api/connections/${row.original.id}/recording.zip` }}>
                <Download className='size-3.5' />
                {t('downloadRecording')}
              </Button>
            ) : null}
            <Button size='sm' variant='outline' onClick={() => void closeSession(row.original.id)}>{t('close')}</Button>
          </div>
        ),
      },
    ],
    [app.data.servers, t]
  )

  return (
    <DataTable
      columns={columns}
      data={sessions}
      emptyTitle={t('sessionsPage.emptyTitle')}
      emptyBody={t('sessionsPage.emptyBody')}
      searchPlaceholder={t('sessionsPage.searchPlaceholder')}
      getSearchText={(session) => [session.id, session.protocol, session.status, session.client_ip, serverName(session.server_id)].filter(Boolean).join(' ')}
    />
  )
}
