import { Link } from '@tanstack/react-router'
import { Activity, Database, KeyRound, Server } from 'lucide-react'

import { useApp } from '@/app/app-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { buttonVariants } from '@/components/ui/button'
import { Card, CardHeader, CardTitle } from '@/components/ui/card'

import { SessionsTable } from './sessions-table'

export function OverviewPage() {
  const app = useApp()
  const active = app.data.sessions.filter((item) => item.status === 'active').length
  const recordings = app.data.sessions.filter((item) => item.recording_path).length

  return (
    <>
      <section className='rounded-xl border border-border bg-[radial-gradient(circle_at_80%_0%,color-mix(in_oklch,var(--info)_12%,transparent),transparent_34%),var(--card)] p-5 shadow-sm'>
        <div className='flex flex-wrap items-center justify-between gap-4'>
          <div>
            <div className='text-xs font-medium tracking-[0.12em] text-muted-foreground uppercase'>Connection Workspace</div>
            <h2 className='mt-2 text-2xl font-semibold tracking-tight'>从服务器资产直接进入 SSH 或 RDP</h2>
            <p className='mt-1 max-w-2xl text-sm text-muted-foreground'>
              第一阶段专注在线连接：登记服务器和凭据后，在服务器列表里打开全屏终端或桌面工作区。
            </p>
          </div>
          <div className='flex flex-wrap gap-2'>
            <Link to='/app/credentials' className={buttonVariants({ variant: 'outline' })}>管理凭据</Link>
            <Link to='/app/servers' className={buttonVariants({ variant: 'primary' })}>打开服务器列表</Link>
          </div>
        </div>
      </section>

      <section className='grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4'>
        <StatCard icon={Server} title='服务器' value={app.data.servers.length} desc='已登记 Linux / Windows 主机' />
        <StatCard icon={KeyRound} title='凭据' value={app.data.credentials.length} desc='SSH 密码、私钥与 RDP 账号' />
        <StatCard icon={Activity} title='活跃会话' value={active} desc='当前仍在运行的连接' />
        <StatCard icon={Database} title='录屏索引' value={recordings} desc='RDP 原始录屏目录' />
      </section>

      <section className='grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.8fr)]'>
        <Card>
          <CardHeader>
            <div>
              <CardTitle>最近会话</CardTitle>
            </div>
            <Link to='/app/sessions' className={buttonVariants({ variant: 'ghost' })}>查看全部</Link>
          </CardHeader>
          <SessionsTable sessions={app.data.sessions.slice(-6).reverse()} />
        </Card>
        <Card>
          <CardHeader>
            <div>
              <CardTitle>快速服务器</CardTitle>
            </div>
            <Link to='/app/servers' className={buttonVariants({ variant: 'ghost' })}>管理</Link>
          </CardHeader>
          {app.data.servers.length ? (
            <div className='grid'>
              {app.data.servers.slice(0, 6).map((server) => (
                <div key={server.id} className='flex items-center justify-between gap-3 border-b border-border px-4 py-3 last:border-b-0'>
                  <span className='min-w-0'>
                    <strong className='block truncate'>{server.name}</strong>
                    <em className='block truncate text-xs not-italic text-muted-foreground'>{server.host}</em>
                  </span>
                  <span className='flex gap-2'>
                    <Button size='sm' variant='primary' onClick={() => app.setModal({ type: 'connect', protocol: 'ssh', serverId: server.id })}>SSH</Button>
                    <Button size='sm' variant='outline' onClick={() => app.setModal({ type: 'connect', protocol: 'rdp', serverId: server.id })}>RDP</Button>
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className='p-4 text-sm text-muted-foreground'>添加第一台服务器后，可以在这里快速发起连接。</div>
          )}
        </Card>
      </section>
    </>
  )
}

function StatCard({ icon: Icon, title, value, desc }: { icon: typeof Server; title: string; value: number; desc: string }) {
  return (
    <Card className='p-4'>
      <div className='flex items-center justify-between gap-3 text-xs font-medium text-muted-foreground'>
        <span>{title}</span>
        <span className='flex size-8 items-center justify-center rounded-lg bg-muted text-foreground'>
          <Icon className='size-4' />
        </span>
      </div>
      <strong className='mt-3 block text-3xl leading-none'>{value}</strong>
      <p className='mt-2 text-xs text-muted-foreground'>{desc}</p>
    </Card>
  )
}
