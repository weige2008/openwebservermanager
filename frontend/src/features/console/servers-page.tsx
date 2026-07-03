import type { ColumnDef } from '@tanstack/react-table'
import { Plus } from 'lucide-react'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { osLabel } from '@/lib/utils'
import type { ManagedServer } from '@/types'

export function ServersPage() {
  const app = useApp()
  const { t } = useTranslation()
  const columns = useMemo<ColumnDef<ManagedServer>[]>(
    () => [
      {
        header: t('name'),
        cell: ({ row }) => (
          <div>
            <strong>{row.original.name}</strong>
            <div className='text-xs text-muted-foreground'>{row.original.description || t('serversPage.noDescription')}</div>
          </div>
        ),
      },
      { header: t('address'), cell: ({ row }) => <span className='font-mono text-xs'>{row.original.host}</span> },
      { header: t('os'), cell: ({ row }) => <Badge tone={row.original.os === 'windows' ? 'info' : 'neutral'}>{osLabel(row.original.os)}</Badge> },
      { header: t('ports'), cell: ({ row }) => `SSH ${row.original.ssh_port || 22} / RDP ${row.original.rdp_port || 3389}` },
      { header: t('group'), accessorFn: (row) => row.group || '-' },
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
    [app, t]
  )

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{t('serversPage.title')}</CardTitle>
          <CardDescription>{t('serversPage.description')}</CardDescription>
        </div>
        <Button variant='primary' onClick={() => app.setModal({ type: 'server' })}>
          <Plus className='size-4' />
          {t('addServer')}
        </Button>
      </CardHeader>
      <DataTable
        columns={columns}
        data={app.data.servers}
        emptyTitle={t('serversPage.emptyTitle')}
        emptyBody={t('serversPage.emptyBody')}
        searchPlaceholder={t('serversPage.searchPlaceholder')}
        getSearchText={(server) => [server.name, server.host, server.os, server.group, server.description].filter(Boolean).join(' ')}
      />
    </Card>
  )
}
