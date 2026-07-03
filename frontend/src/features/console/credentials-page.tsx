import type { ColumnDef } from '@tanstack/react-table'
import { Plus } from 'lucide-react'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { credentialLabel, formatDate } from '@/lib/utils'
import type { Credential } from '@/types'

export function CredentialsPage() {
  const app = useApp()
  const { t } = useTranslation()
  const columns = useMemo<ColumnDef<Credential>[]>(
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
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{t('credentialsPage.title')}</CardTitle>
          <CardDescription>{t('credentialsPage.description')}</CardDescription>
        </div>
        <Button variant='primary' onClick={() => app.setModal({ type: 'credential' })}>
          <Plus className='size-4' />
          {t('addCredential')}
        </Button>
      </CardHeader>
      <DataTable
        columns={columns}
        data={app.data.credentials}
        emptyTitle={t('credentialsPage.emptyTitle')}
        emptyBody={t('credentialsPage.emptyBody')}
        searchPlaceholder={t('credentialsPage.searchPlaceholder')}
        getSearchText={(credential) => [credential.name, credential.type, credential.username, credential.domain].filter(Boolean).join(' ')}
      />
    </Card>
  )
}
