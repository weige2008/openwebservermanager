import { Link } from '@tanstack/react-router'
import {
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  CloudCog,
  DatabaseZap,
  Download,
  FileUp,
  KeyRound,
  LockKeyhole,
  MonitorUp,
  Network,
  RadioTower,
  Server,
  ShieldCheck,
  TerminalSquare,
  type LucideIcon,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { PublicHeader } from '@/components/layout/public-header'
import { Button, buttonVariants } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { cn } from '@/lib/utils'

type Pair = [string, string]
type Step = [string, string, string]

interface HomeCopy {
  badge: string
  heroBody: string
  viewProduct: string
  highlights: string[]
  productTitle: string
  productBody: string
  capabilities: Pair[]
  connectionsTitle: string
  connectionsBody: string
  openWorkspace: string
  connectionCards: Pair[]
  securityTitle: string
  securityBody: string
  securityItems: Pair[]
  workflowEyebrow: string
  workflowTitle: string
  workflowBody: string
  workflowSteps: Step[]
  deployTitle: string
  deployBody: string
  footerBody: string
  footerBuilt: string
  footerProduct: string
  footerLinks: string[]
  preview: {
    workspace: string
    servers: string[]
    rdpDesktop: string
    upload: string
    recording: string
    latency: string
    terminalWelcome: string
    terminalStatus: string
  }
}

const capabilityIcons = [Server, DatabaseZap, RadioTower, CloudCog]
const connectionIcons = [TerminalSquare, MonitorUp, ClipboardCheck]
const securityIcons = [LockKeyhole, KeyRound, ShieldCheck]

export function HomePage() {
  const { auth, publicConfig, setupRequired } = useApp()
  const { t } = useTranslation()
  const copy = t('home', { returnObjects: true }) as HomeCopy
  const authenticated = Boolean(auth)
  const entryTo = authenticated ? '/app' : '/login'
  const entryText = authenticated ? t('enterConsole') : setupRequired ? t('initializeAdmin') : t('signInConsole')
  const siteName = publicConfig.site_name || 'ServerManager'

  return (
    <div className='min-h-svh overflow-x-clip bg-background text-foreground'>
      <PublicHeader authenticated={authenticated} />
      <main>
        <section className='relative isolate overflow-hidden border-b border-border bg-background pt-24 pb-10 md:pt-28 lg:min-h-[min(760px,82svh)]'>
          <div aria-hidden='true' className='absolute inset-0 bg-[linear-gradient(180deg,color-mix(in_oklch,var(--muted)_42%,transparent)_0%,transparent_42%)]' />
          <div className='absolute inset-x-0 bottom-0 h-32 bg-gradient-to-t from-background to-transparent' aria-hidden='true' />
          <div className='relative z-10 mx-auto grid w-[min(72rem,calc(100%-2rem))] items-center gap-8 lg:grid-cols-[minmax(0,0.82fr)_minmax(390px,0.9fr)] lg:gap-10'>
            <div className='max-w-2xl lg:max-w-[35rem]'>
              <div className='landing-animate inline-flex max-w-full items-center gap-2 rounded-full border border-border bg-background/75 px-3 py-1.5 text-[11px] font-medium text-muted-foreground shadow-sm backdrop-blur-xl'>
                <span className='pulse-dot relative size-1.5 shrink-0 rounded-full bg-success before:absolute before:inset-0 before:rounded-full before:bg-success' />
                <span className='truncate'>{copy.badge}</span>
              </div>
              <h1 className='landing-animate mt-5 text-[clamp(2.7rem,5.6vw,4.65rem)] leading-[0.96] font-semibold tracking-tight' style={{ animationDelay: '60ms' }}>
                {siteName}
              </h1>
              <p className='landing-animate mt-6 max-w-xl text-base leading-8 text-foreground/70 md:text-lg' style={{ animationDelay: '120ms' }}>
                {copy.heroBody}
              </p>
              <div className='landing-animate mt-8 flex flex-wrap items-center gap-3' style={{ animationDelay: '180ms' }}>
                <Link to={entryTo} className={cn(buttonVariants({ variant: 'primary', size: 'lg' }), 'h-10 px-4')}>
                  {entryText}
                  <ArrowRight className='size-4' />
                </Link>
                <Button variant='outline' size='lg' className='h-10 px-4' onClick={() => document.querySelector('#product')?.scrollIntoView({ behavior: 'smooth' })}>
                  {copy.viewProduct}
                </Button>
              </div>
              <div className='landing-animate mt-8 grid max-w-xl grid-cols-2 gap-2 sm:grid-cols-4' style={{ animationDelay: '240ms' }}>
                {copy.highlights.map((item) => (
                  <span key={item} className='rounded-lg border border-border bg-background/70 px-3 py-2 text-xs font-medium text-muted-foreground shadow-sm backdrop-blur-xl'>
                    {item}
                  </span>
                ))}
              </div>
            </div>
            <HeroOperationsPreview copy={copy} />
          </div>
        </section>

        <section id='product' className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-8 py-16 lg:grid-cols-[0.9fr_1.1fr]'>
          <SectionIntro eyebrow={t('product')} title={copy.productTitle} body={copy.productBody} />
          <div className='grid gap-3 sm:grid-cols-2'>
            {copy.capabilities.map(([title, body], index) => (
              <CapabilityTile key={title} icon={capabilityIcons[index]} title={title} body={body} />
            ))}
          </div>
        </section>

        <section id='connections' className='border-y border-border bg-muted/30 py-16'>
          <div className='mx-auto w-[min(72rem,calc(100%-2rem))]'>
            <div className='mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-end'>
              <SectionIntro eyebrow={t('connections')} title={copy.connectionsTitle} body={copy.connectionsBody} />
              <Link to={entryTo} className={cn(buttonVariants({ variant: 'outline', size: 'lg' }), 'h-10 px-4')}>
                {copy.openWorkspace}
                <ChevronRight className='size-4' />
              </Link>
            </div>
            <div className='grid grid-cols-1 gap-3 md:grid-cols-3'>
              {copy.connectionCards.map(([title, body], index) => (
                <FeatureCard key={title} icon={connectionIcons[index]} title={title} body={body} />
              ))}
            </div>
          </div>
        </section>

        <section id='security' className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-8 py-16 lg:grid-cols-[0.82fr_1.18fr]'>
          <SectionIntro eyebrow={t('security')} title={copy.securityTitle} body={copy.securityBody} />
          <div className='grid gap-3'>
            {copy.securityItems.map(([title, body], index) => (
              <SecurityRow key={title} icon={securityIcons[index]} title={title} body={body} />
            ))}
          </div>
        </section>

        <section id='deploy' className='border-y border-border bg-card/45 py-16'>
          <div className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-8 lg:grid-cols-[1fr_0.9fr]'>
            <div>
              <SectionIntro eyebrow={copy.workflowEyebrow} title={copy.workflowTitle} body={copy.workflowBody} />
              <div className='mt-8 grid gap-3 sm:grid-cols-2'>
                {copy.workflowSteps.map(([index, title, body]) => (
                  <WorkflowStep key={index} index={index} title={title} body={body} />
                ))}
              </div>
            </div>
            <DeploymentPanel title={copy.deployTitle} body={copy.deployBody} />
          </div>
        </section>
      </main>
      <PublicFooter siteName={siteName} entryTo={entryTo} entryText={entryText} copy={copy} />
    </div>
  )
}

function HeroOperationsPreview({ copy }: { copy: HomeCopy }) {
  return (
    <div className='landing-animate w-full max-w-[34rem] justify-self-center lg:justify-self-end' style={{ animationDelay: '140ms' }}>
      <div className='overflow-hidden rounded-2xl border border-border/80 bg-card/85 shadow-2xl backdrop-blur-xl'>
        <div className='flex h-11 min-w-0 items-center gap-2 border-b border-border px-4'>
          <span className='size-2.5 shrink-0 rounded-full bg-destructive' />
          <span className='size-2.5 shrink-0 rounded-full bg-warning' />
          <span className='size-2.5 shrink-0 rounded-full bg-success' />
          <span className='ml-2 min-w-0 truncate rounded-md bg-muted px-2 py-1 font-mono text-[11px] text-muted-foreground sm:ml-4'>{copy.preview.workspace}</span>
        </div>
        <div className='grid min-h-[340px] grid-cols-[8rem_minmax(0,1fr)] sm:min-h-[410px] sm:grid-cols-[11rem_minmax(0,1fr)]'>
          <div className='min-w-0 border-r border-border bg-muted/35 p-3 sm:p-4'>
            <div className='mb-4 h-7 rounded-lg bg-background/80' />
            {copy.preview.servers.map((item, index) => (
              <div key={item} className={cn('mb-2 rounded-lg border p-2 text-[11px] sm:p-3 sm:text-xs', index === 1 ? 'border-info/40 bg-info/10 text-foreground' : 'border-border bg-card/75 text-muted-foreground')}>
                <div className='mb-2 flex min-w-0 items-center gap-2'>
                  <span className={cn('size-2 shrink-0 rounded-full', index === 2 ? 'bg-warning' : 'bg-success')} />
                  <span className='truncate font-medium'>{item}</span>
                </div>
                <div className='truncate font-mono text-[10px] opacity-75'>10.18.{index + 12}.24</div>
              </div>
            ))}
          </div>
          <div className='grid min-w-0 content-start gap-3 p-3 sm:p-4'>
            <div className='grid gap-3 xl:grid-cols-[1fr_0.72fr]'>
              <div className='rounded-xl bg-[#050507] p-3 font-mono text-[11px] leading-6 text-zinc-300 shadow-[inset_0_0_0_1px_rgb(255_255_255_/_0.08)] sm:p-4'>
                <div>$ ssh ubuntu@10.18.12.24</div>
                <div>{copy.preview.terminalWelcome}</div>
                <div>$ systemctl status app</div>
                <div className='text-emerald-300'>{copy.preview.terminalStatus}</div>
              </div>
              <div className='rounded-xl border border-border bg-[linear-gradient(180deg,color-mix(in_oklch,var(--info)_18%,var(--card)),var(--card))] p-3'>
                <div className='mb-3 flex items-center justify-between gap-2 text-[11px] text-muted-foreground'>
                  <span>{copy.preview.rdpDesktop}</span>
                  <span>1920 x 1080</span>
                </div>
                <div className='h-20 rounded-lg bg-background/70 sm:h-24' />
                <div className='mt-3 grid grid-cols-3 gap-2'>
                  <span className='h-7 rounded-md bg-background/60 sm:h-8' />
                  <span className='h-7 rounded-md bg-background/60 sm:h-8' />
                  <span className='h-7 rounded-md bg-background/60 sm:h-8' />
                </div>
              </div>
            </div>
            <div className='grid grid-cols-1 gap-2 sm:grid-cols-3 sm:gap-3'>
              <SceneMetric icon={FileUp} label={copy.preview.upload} value='24 MB' />
              <SceneMetric icon={Download} label={copy.preview.recording} value='00:18:42' />
              <SceneMetric icon={Network} label={copy.preview.latency} value='28 ms' />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function SceneMetric({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: string }) {
  return (
    <div className='rounded-xl border border-border bg-card/75 p-3'>
      <Icon className='mb-2 size-4 text-muted-foreground sm:mb-3' />
      <div className='text-xs text-muted-foreground'>{label}</div>
      <div className='mt-1 font-mono text-sm font-semibold'>{value}</div>
    </div>
  )
}

function SectionIntro({ eyebrow, title, body }: { eyebrow: string; title: string; body: string }) {
  return (
    <div className='max-w-2xl'>
      <div className='text-xs font-semibold tracking-[0.14em] text-muted-foreground uppercase'>{eyebrow}</div>
      <h2 className='mt-3 text-2xl leading-tight font-semibold tracking-tight md:text-3xl'>{title}</h2>
      <p className='mt-4 text-sm leading-7 text-muted-foreground'>{body}</p>
    </div>
  )
}

function CapabilityTile({ icon: Icon, title, body }: { icon: LucideIcon; title: string; body: string }) {
  return (
    <article className='rounded-xl border border-border bg-card p-5 shadow-sm'>
      <Icon className='mb-5 size-5 text-muted-foreground' />
      <h3 className='text-sm font-semibold'>{title}</h3>
      <p className='mt-2 text-sm leading-6 text-muted-foreground'>{body}</p>
    </article>
  )
}

function FeatureCard({ icon: Icon, title, body }: { icon: LucideIcon; title: string; body: string }) {
  return (
    <Card className='p-5 shadow-sm' data-card-hover='false'>
      <Icon className='mb-5 size-5 text-muted-foreground' />
      <h3 className='text-sm font-semibold'>{title}</h3>
      <p className='text-sm leading-6 text-muted-foreground'>{body}</p>
    </Card>
  )
}

function SecurityRow({ icon: Icon, title, body }: { icon: LucideIcon; title: string; body: string }) {
  return (
    <article className='grid grid-cols-[2.25rem_1fr] gap-4 rounded-xl border border-border bg-card p-5 shadow-sm'>
      <span className='grid size-9 place-items-center rounded-lg bg-muted text-muted-foreground'>
        <Icon className='size-4' />
      </span>
      <div>
        <h3 className='text-sm font-semibold'>{title}</h3>
        <p className='mt-1 text-sm leading-6 text-muted-foreground'>{body}</p>
      </div>
    </article>
  )
}

function WorkflowStep({ index, title, body }: { index: string; title: string; body: string }) {
  return (
    <article className='rounded-xl border border-border bg-background p-5 shadow-sm'>
      <span className='font-mono text-xs font-semibold text-muted-foreground'>{index}</span>
      <h3 className='mt-3 text-sm font-semibold'>{title}</h3>
      <p className='mt-2 text-sm leading-6 text-muted-foreground'>{body}</p>
    </article>
  )
}

function DeploymentPanel({ title, body }: { title: string; body: string }) {
  return (
    <aside className='self-start rounded-xl border border-border bg-background p-5 shadow-sm lg:sticky lg:top-24'>
      <div className='mb-5 flex items-center justify-between gap-3'>
        <div>
          <h3 className='text-sm font-semibold'>{title}</h3>
          <p className='mt-1 text-xs text-muted-foreground'>{body}</p>
        </div>
        <CheckCircle2 className='size-5 text-success' />
      </div>
      <div className='grid gap-2 font-mono text-xs'>
        <div className='rounded-lg bg-muted p-3'>SERVERMANAGER_ADDR=0.0.0.0:23876</div>
        <div className='rounded-lg bg-muted p-3'>SERVERMANAGER_DATA_DIR=/opt/servermanager/data</div>
        <div className='rounded-lg bg-muted p-3'>SERVERMANAGER_GUACD_HOST=127.0.0.1</div>
      </div>
      <div className='mt-5 grid grid-cols-2 gap-2 text-xs text-muted-foreground'>
        <span className='rounded-lg border border-border px-3 py-2'>Linux</span>
        <span className='rounded-lg border border-border px-3 py-2'>Windows</span>
        <span className='rounded-lg border border-border px-3 py-2'>SQLite</span>
        <span className='rounded-lg border border-border px-3 py-2'>guacd</span>
      </div>
    </aside>
  )
}

function PublicFooter({ siteName, entryTo, entryText, copy }: { siteName: string; entryTo: string; entryText: string; copy: HomeCopy }) {
  return (
    <footer className='border-t border-border bg-background'>
      <div className='mx-auto grid w-[min(72rem,calc(100%-2rem))] gap-8 py-10 md:grid-cols-[1.2fr_0.8fr_0.8fr]'>
        <div>
          <div className='inline-flex items-center gap-2 text-sm font-semibold'>
            <span className='grid size-6 place-items-center rounded-md bg-primary text-primary-foreground'>
              <span className='size-3 rounded-sm bg-primary-foreground/90' />
            </span>
            {siteName}
          </div>
          <p className='mt-3 max-w-sm text-sm leading-6 text-muted-foreground'>{copy.footerBody}</p>
        </div>
        <FooterColumn
          title={copy.footerProduct}
          links={[
            [copy.footerLinks[0], '#product'],
            [copy.footerLinks[1], '#connections'],
            [copy.footerLinks[2], '#security'],
            [copy.footerLinks[3], '#deploy'],
          ]}
        />
        <div>
          <h3 className='text-xs font-semibold tracking-[0.12em] text-muted-foreground uppercase'>Console</h3>
          <Link to={entryTo} className={cn(buttonVariants({ variant: 'outline', size: 'lg' }), 'mt-4 h-10 w-full px-4 md:w-auto')}>
            {entryText}
            <ArrowRight className='size-4' />
          </Link>
        </div>
      </div>
      <div className='mx-auto flex w-[min(72rem,calc(100%-2rem))] flex-col gap-2 border-t border-border py-5 text-xs text-muted-foreground sm:flex-row sm:items-center sm:justify-between'>
        <span>© 2026 {siteName}. Self-hosted server operations console.</span>
        <span>{copy.footerBuilt}</span>
      </div>
    </footer>
  )
}

function FooterColumn({ title, links }: { title: string; links: Array<[string, string]> }) {
  return (
    <nav>
      <h3 className='text-xs font-semibold tracking-[0.12em] text-muted-foreground uppercase'>{title}</h3>
      <div className='mt-4 grid gap-2'>
        {links.map(([label, href]) => (
          <a key={href} href={href} className='text-sm text-muted-foreground transition-colors hover:text-foreground'>
            {label}
          </a>
        ))}
      </div>
    </nav>
  )
}
