import type { ColumnDef } from '@tanstack/react-table'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { CardStaggerContainer, CardStaggerItem } from '@/components/page-transition'
import { DataTable } from '@/components/data-table/data-table'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { formatDate } from '@/lib/utils'
import type { AuditLog } from '@/types'

export function AuditPage() {
  const { data } = useApp()
  const { t } = useTranslation()
  const columns = useMemo<ColumnDef<AuditLog>[]>(
    () => [
      { header: t('time'), cell: ({ row }) => formatDate(row.original.created_at) },
      { header: t('action'), cell: ({ row }) => <span className='font-mono text-xs'>{row.original.action}</span> },
      { header: t('target'), accessorFn: (row) => row.target_id || '-' },
      { header: t('protocol'), accessorFn: (row) => row.protocol || '-' },
      { header: t('source'), accessorFn: (row) => row.client_ip || '-' },
      { header: t('details'), accessorFn: (row) => row.detail || '' },
    ],
    [t]
  )

  return (
    <CardStaggerContainer>
      <CardStaggerItem>
        <Card>
          <CardHeader>
            <div>
              <CardTitle>{t('auditPage.title')}</CardTitle>
              <CardDescription>{t('auditPage.description')}</CardDescription>
            </div>
          </CardHeader>
          <DataTable
            columns={columns}
            data={[...data.audit_logs].reverse()}
            emptyTitle={t('auditPage.emptyTitle')}
            emptyBody={t('auditPage.emptyBody')}
            searchPlaceholder={t('auditPage.searchPlaceholder')}
            getSearchText={(log) => [log.action, log.target_id, log.protocol, log.client_ip, log.detail, log.user_id].filter(Boolean).join(' ')}
          />
        </Card>
      </CardStaggerItem>
    </CardStaggerContainer>
  )
}
