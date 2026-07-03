import { useApp } from '@/app/app-provider'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

import { SessionsTable } from './sessions-table'

export function SessionsPage() {
  const { data } = useApp()
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>连接会话</CardTitle>
          <CardDescription>包含协议、目标服务器、状态、来源 IP 与录屏索引。</CardDescription>
        </div>
      </CardHeader>
      <SessionsTable sessions={[...data.sessions].reverse()} />
    </Card>
  )
}
