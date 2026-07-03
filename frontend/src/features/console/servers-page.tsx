import type { ColumnDef } from '@tanstack/react-table'
import { Plus } from 'lucide-react'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { credentialLabel, formatDate, osLabel } from '@/lib/utils'
import type { Credential, ManagedServer } from '@/types'

export function ServersPage() {
  const app = useApp()
  const { t } = useTranslation()
  const sshCredentials = useMemo(
    () => app.data.credentials.filter((credential) => credential.type === 'ssh_password' || credential.type === 'ssh_key'),
    [app.data.credentials]
  )
  const rdpCredentials = useMemo(
    () => app.data.credentials.filter((credential) => credential.type === 'rdp_password'),
    [app.data.credentials]
  )
  const serverColumns = useMemo<ColumnDef<ManagedServer>[]>(
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
      {
        header: t('credentials'),
        cell: () => (
          <div className='flex flex-wrap gap-1.5'>
            <Badge tone={sshCredentials.length ? 'success' : 'warning'}>SSH {sshCredentials.length}</Badge>
            <Badge tone={rdpCredentials.length ? 'success' : 'warning'}>RDP {rdpCredentials.length}</Badge>
          </div>
        ),
      },
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
    [app, rdpCredentials.length, sshCredentials.length, t]
  )
  const credentialColumns = useMemo<ColumnDef<Credential>[]>(
    () => [
      { header: t('name'), cell: ({ row }) => <strong>{row.original.name}</strong> },
      { header: t('type'), cell: ({ row }) => <Badge>{credentialLabel(row.original.type)}</Badge> },
      { header: t('username'), accessorFn: (row) => row.username },
      { header: t('domainWorkgroup'), accessorFn: (row) => row.domain || '-' },
      { header: t('createdAt'), cell: ({ row }) => formatDate(row.original.created_at) },
    ],
    [t]
  )

  return (
    <div className='grid gap-4'>
      <Card>
        <CardHeader className='gap-3 max-sm:grid-cols-1'>
          <div>
            <CardTitle>{t('servers')} / {t('credentials')}</CardTitle>
            <CardDescription>{t('serversPage.description')}</CardDescription>
          </div>
          <div className='flex flex-wrap justify-end gap-2 max-sm:justify-start'>
            <Button variant='outline' onClick={() => app.setModal({ type: 'credential' })}>
              <Plus className='size-4' />
              {t('addCredential')}
            </Button>
            <Button variant='primary' onClick={() => app.setModal({ type: 'server' })}>
              <Plus className='size-4' />
              {t('addServer')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={serverColumns}
            data={app.data.servers}
            emptyTitle={t('serversPage.emptyTitle')}
            emptyBody={t('serversPage.emptyBody')}
            searchPlaceholder={t('serversPage.searchPlaceholder')}
            getSearchText={(server) => [server.name, server.host, server.os, server.group, server.description].filter(Boolean).join(' ')}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className='gap-3 max-sm:grid-cols-1'>
          <div>
            <CardTitle>{t('credentialsPage.title')}</CardTitle>
            <CardDescription>{t('credentialsPage.description')}</CardDescription>
          </div>
          <Button variant='outline' onClick={() => app.setModal({ type: 'credential' })}>
            <Plus className='size-4' />
            {t('addCredential')}
          </Button>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={credentialColumns}
            data={app.data.credentials}
            emptyTitle={t('credentialsPage.emptyTitle')}
            emptyBody={t('credentialsPage.emptyBody')}
            searchPlaceholder={t('credentialsPage.searchPlaceholder')}
            getSearchText={(credential) => [credential.name, credential.type, credential.username, credential.domain].filter(Boolean).join(' ')}
          />
        </CardContent>
      </Card>
    </div>
  )
}
