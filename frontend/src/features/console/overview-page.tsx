import { Link } from '@tanstack/react-router'
import { Activity, Database, KeyRound, RadioTower, Server, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { buttonVariants } from '@/components/ui/button'
import { Card, CardHeader, CardTitle } from '@/components/ui/card'
import { serverProtocol } from '@/lib/utils'

import { SessionsTable } from './sessions-table'

type StatTone = 'rose' | 'teal' | 'info' | 'warning'

const toneClasses: Record<StatTone, { icon: string; line: string; bars: string }> = {
  rose: {
    icon: 'bg-rose-500/10 text-rose-600 ring-rose-500/20 dark:text-rose-300',
    line: 'text-rose-500 dark:text-rose-300',
    bars: 'from-rose-500/80 via-rose-300/70 to-rose-200/20 dark:from-rose-400/70 dark:via-rose-500/30 dark:to-rose-500/5',
  },
  teal: {
    icon: 'bg-teal-500/10 text-teal-600 ring-teal-500/20 dark:text-teal-300',
    line: 'text-teal-600 dark:text-teal-300',
    bars: 'from-teal-500/80 via-teal-300/70 to-teal-200/20 dark:from-teal-400/70 dark:via-teal-500/30 dark:to-teal-500/5',
  },
  info: {
    icon: 'bg-info/12 text-info ring-info/25',
    line: 'text-info',
    bars: 'from-info/80 via-info/35 to-info/10',
  },
  warning: {
    icon: 'bg-warning/15 text-warning ring-warning/25',
    line: 'text-warning',
    bars: 'from-warning/80 via-warning/35 to-warning/10',
  },
}

export function OverviewPage() {
  const app = useApp()
  const { t } = useTranslation()
  const active = app.data.sessions.filter((item) => item.status === 'active').length
  const recordings = app.data.sessions.filter((item) => item.recording_path).length
  const gatewayOnline = Boolean(app.data.guacd?.address)
  const sshSessions = app.data.sessions.filter((item) => item.protocol === 'ssh').length
  const rdpSessions = app.data.sessions.filter((item) => item.protocol === 'rdp').length

  return (
    <>
      <section className='overflow-hidden rounded-2xl border border-border bg-card shadow-sm'>
        <div className='grid xl:grid-cols-[minmax(0,1fr)_19rem]'>
          <div className='flex flex-col gap-4 p-4 sm:p-5'>
            <div className='flex flex-wrap items-start justify-between gap-4'>
              <div className='min-w-0'>
                <div className='text-xs font-medium tracking-[0.12em] text-muted-foreground uppercase'>{t('overviewPage.eyebrow')}</div>
                <h2 className='mt-2 text-2xl font-semibold tracking-tight'>{t('overviewPage.title')}</h2>
                <p className='mt-1 max-w-2xl text-sm text-muted-foreground'>{t('overviewPage.description')}</p>
              </div>
              <div className='flex flex-wrap gap-2'>
                <Link to='/app/servers' className={buttonVariants({ variant: 'outline' })}>{t('overviewPage.manageCredentials')}</Link>
                <Link to='/app/servers' className={buttonVariants({ variant: 'primary' })}>{t('overviewPage.openServers')}</Link>
              </div>
            </div>

            <div className='grid gap-3 md:grid-cols-2 xl:grid-cols-4'>
              <SummaryStatCard icon={Server} title={t('overviewPage.serverCount')} value={app.data.servers.length} desc={t('overviewPage.serverCountDesc')} tone='rose' sparkline={makeSparkline(app.data.servers.length, 3)} />
              <SummaryStatCard icon={KeyRound} title={t('overviewPage.credentialCount')} value={app.data.credentials.length} desc={t('overviewPage.credentialCountDesc')} tone='teal' sparkline={makeSparkline(app.data.credentials.length, 5)} />
              <SummaryStatCard icon={Activity} title={t('overviewPage.activeSessions')} value={active} desc={t('overviewPage.activeSessionsDesc')} tone='info' sparkline={makeSparkline(active, 7)} />
              <SummaryStatCard icon={Database} title={t('overviewPage.recordingIndexes')} value={recordings} desc={t('overviewPage.recordingIndexesDesc')} tone='warning' sparkline={makeSparkline(recordings, 11)} />
            </div>
          </div>

          <div className={gatewayOnline ? 'flex flex-col justify-between gap-4 border-t border-border bg-success/10 p-4 sm:p-5 xl:border-t-0 xl:border-l' : 'flex flex-col justify-between gap-4 border-t border-border bg-warning/10 p-4 sm:p-5 xl:border-t-0 xl:border-l'}>
            <div className='grid gap-3'>
              <div className='flex items-center justify-between gap-3'>
                <span className='text-xs font-medium text-muted-foreground'>{t('gateway')}</span>
                <Badge tone={gatewayOnline ? 'success' : 'warning'}>{gatewayOnline ? t('gatewayReady') : t('gatewayOffline')}</Badge>
              </div>
              <div className='font-mono text-2xl font-semibold tracking-tight'>{gatewayOnline ? app.data.guacd?.address : t('guacdOffline')}</div>
              <p className='text-sm leading-6 text-muted-foreground'>{gatewayOnline ? t('rdpGatewayOnline') : t('rdpGatewayOfflineBody')}</p>
            </div>
            <div className='grid grid-cols-2 gap-2'>
              <MiniMetric icon={RadioTower} label='SSH' value={sshSessions} tone='success' />
              <MiniMetric icon={ShieldCheck} label='RDP' value={rdpSessions} tone='info' />
            </div>
          </div>
        </div>
      </section>

      <section className='grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.8fr)]'>
        <Card>
          <CardHeader>
            <div>
              <CardTitle>{t('overviewPage.recentSessions')}</CardTitle>
            </div>
            <Link to='/app/sessions' className={buttonVariants({ variant: 'ghost' })}>{t('overviewPage.viewAll')}</Link>
          </CardHeader>
          <SessionsTable sessions={app.data.sessions.slice(-6).reverse()} />
        </Card>
        <Card>
          <CardHeader>
            <div>
              <CardTitle>{t('overviewPage.quickServers')}</CardTitle>
            </div>
            <Link to='/app/servers' className={buttonVariants({ variant: 'ghost' })}>{t('overviewPage.manage')}</Link>
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
                    {(() => {
                      const protocol = serverProtocol(server)
                      return (
                        <Button size='sm' variant={protocol === 'rdp' ? 'outline' : 'primary'} onClick={() => app.setModal({ type: 'connect', protocol, serverId: server.id })}>
                          {protocol.toUpperCase()}
                        </Button>
                      )
                    })()}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className='p-4 text-sm text-muted-foreground'>{t('overviewPage.noQuickServers')}</div>
          )}
        </Card>
      </section>
    </>
  )
}

function SummaryStatCard({ icon: Icon, title, value, desc, tone, sparkline }: { icon: typeof Server; title: string; value: number; desc: string; tone: StatTone; sparkline: number[] }) {
  const classes = toneClasses[tone]

  return (
    <article className='flex min-h-36 flex-col justify-between gap-3 rounded-xl border border-border bg-background/60 p-3'>
      <div className='flex items-start justify-between gap-3'>
        <div className='flex min-w-0 items-center gap-2 text-xs font-medium text-muted-foreground'>
          <span className={`grid size-8 shrink-0 place-items-center rounded-lg ring-1 ${classes.icon}`}>
            <Icon className='size-4' />
          </span>
          <span className='line-clamp-2 leading-snug'>{title}</span>
        </div>
      </div>
      <div>
        <strong className='block font-mono text-3xl leading-none font-semibold tracking-tight tabular-nums'>{value}</strong>
        <p className='mt-2 line-clamp-2 text-xs leading-relaxed text-muted-foreground/70'>{desc}</p>
      </div>
      <BarSparkline values={sparkline} tone={tone} />
    </article>
  )
}

function BarSparkline({ values, tone }: { values: number[]; tone: StatTone }) {
  const max = Math.max(...values, 1)

  return (
    <div className='flex h-8 items-end gap-1' aria-hidden='true'>
      {values.map((value, index) => (
        <span
          key={index}
          className={`flex-1 rounded-t-sm bg-linear-to-t ${toneClasses[tone].bars}`}
          style={{ height: `${Math.max(10, (value / max) * 100)}%` }}
        />
      ))}
    </div>
  )
}

function MiniMetric({ icon: Icon, label, value, tone }: { icon: typeof Server; label: string; value: number; tone: 'success' | 'info' }) {
  return (
    <div className='rounded-lg bg-background/60 px-2.5 py-2'>
      <div className='flex items-center gap-1 text-[11px] leading-none font-medium text-muted-foreground'>
        <Icon className={`size-3 shrink-0 ${tone === 'success' ? 'text-success' : 'text-info'}`} />
        <span>{label}</span>
      </div>
      <div className='mt-1.5 font-mono text-xs font-semibold tabular-nums'>{value}</div>
    </div>
  )
}

function makeSparkline(value: number, seed: number) {
  const base = Math.max(1, value)
  return Array.from({ length: 12 }, (_, index) => {
    const wave = ((index + seed) * (seed + 3)) % 7
    return base + wave + (index % 3)
  })
}
