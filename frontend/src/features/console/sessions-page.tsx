import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { CardStaggerContainer, CardStaggerItem } from '@/components/page-transition'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

import { SessionsTable } from './sessions-table'

export function SessionsPage() {
  const { data } = useApp()
  const { t } = useTranslation()

  return (
    <CardStaggerContainer>
      <CardStaggerItem>
        <Card>
          <CardHeader>
            <div>
              <CardTitle>{t('sessionsPage.title')}</CardTitle>
              <CardDescription>{t('sessionsPage.description')}</CardDescription>
            </div>
          </CardHeader>
          <SessionsTable sessions={[...data.sessions].reverse()} />
        </Card>
      </CardStaggerItem>
    </CardStaggerContainer>
  )
}
