import type { ColumnDef } from '@tanstack/react-table'
import { KeyRound, Plus, ServerCog } from 'lucide-react'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { credentialLabel, credentialsForServer, formatDate, osLabel, serverProtocol } from '@/lib/utils'
import type { Credential, ManagedServer, Protocol } from '@/types'

export function ServersPage() {
  const app = useApp()
  const { t } = useTranslation()
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
      { header: t('ports'), cell: ({ row }) => row.original.os === 'windows' ? `RDP ${row.original.rdp_port || 3389}` : `SSH ${row.original.ssh_port || 22}` },
      {
        header: t('connectionAccounts'),
        cell: ({ row }) => <ServerCredentials server={row.original} credentials={app.data.credentials} />,
      },
      { header: t('group'), accessorFn: (row) => row.group || '-' },
      { header: t('createdAt'), cell: ({ row }) => formatDate(row.original.created_at) },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => <ServerActions server={row.original} />,
      },
    ],
    [app.data.credentials, t]
  )

  return (
    <Card>
      <CardHeader className='gap-3 max-sm:grid-cols-1'>
        <div>
          <CardTitle className='flex items-center gap-2'>
            <ServerCog className='size-5 text-primary' />
            {t('serversPage.title')}
          </CardTitle>
          <CardDescription>{t('serversPage.description')}</CardDescription>
        </div>
        <div className='flex flex-wrap justify-end gap-2 max-sm:justify-start'>
          <Button variant='primary' onClick={() => app.setModal({ type: 'server' })}>
            <Plus className='size-4' />
            {t('addAsset')}
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
          getSearchText={(server) => {
            const credentials = credentialsForServer(app.data.credentials, server)
            return [
              server.name,
              server.host,
              server.os,
              server.group,
              server.description,
              ...credentials.flatMap((credential) => [credential.name, credential.username, credential.type, credential.domain]),
            ].filter(Boolean).join(' ')
          }}
        />
      </CardContent>
    </Card>
  )
}

function ServerCredentials({ server, credentials }: { server: ManagedServer; credentials: Credential[] }) {
  const { t } = useTranslation()
  const items = credentialsForServer(credentials, server)

  if (!items.length) {
    return <span className='text-xs text-muted-foreground'>{t('serversPage.noCredentials')}</span>
  }

  return (
    <div className='grid max-w-80 gap-1.5'>
      {items.slice(0, 3).map((credential) => (
        <div key={credential.id} className='flex min-w-0 items-center gap-1.5'>
          <Badge tone={credential.server_id ? 'success' : 'neutral'} className='max-w-full'>
            <span className='truncate'>{credential.name}</span>
          </Badge>
          <span className='min-w-0 truncate text-xs text-muted-foreground'>
            {credential.username} · {credentialLabel(credential.type)}
          </span>
        </div>
      ))}
      {items.length > 3 ? <Badge tone='info'>+{items.length - 3}</Badge> : null}
    </div>
  )
}

function ServerActions({ server }: { server: ManagedServer }) {
  const app = useApp()
  const { t } = useTranslation()
  const protocol = serverProtocol(server)

  return (
    <div className='flex justify-end gap-1.5'>
      <Button
        size='sm'
        variant='outline'
        title={t('serversPage.addCredentialForServer')}
        onClick={() => app.setModal({ type: 'credential', serverId: server.id })}
      >
        <KeyRound className='size-3.5' />
        <span className='hidden xl:inline'>{t('addCredential')}</span>
      </Button>
      <ConnectButton protocol={protocol} server={server} />
    </div>
  )
}

function ConnectButton({ protocol, server }: { protocol: Protocol; server: ManagedServer }) {
  const app = useApp()

  return (
    <Button
      size='sm'
      variant={protocol === 'rdp' ? 'outline' : 'primary'}
      onClick={() => app.setModal({ type: 'connect', protocol, serverId: server.id })}
    >
      {protocol.toUpperCase()}
    </Button>
  )
}
