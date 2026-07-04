import { Link } from '@tanstack/react-router'
import {
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  CloudCog,
  Code2,
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
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { BrandLogo } from '@/components/layout/brand-logo'
import { PublicHeader } from '@/components/layout/public-header'
import { Button, buttonVariants } from '@/components/ui/button'
import { resolvePublicHref } from '@/lib/public-navigation'
import { cn } from '@/lib/utils'

type Pair = [string, string]
type Step = [string, string, string]
type AccentTone = 'emerald' | 'amber' | 'blue' | 'violet'

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

interface DemoConfig {
  id: string
  label: string
  method: 'SSH' | 'RDP' | 'FILE' | 'AUDIT'
  endpoint: string
  accent: AccentTone
  status: string
  latency: number
  rows: Array<{ kind: 'command' | 'muted' | 'success' | 'warning' | 'key'; text: string }>
  metrics: Array<[string, string]>
}

const ACCENT_CLASSES: Record<
  AccentTone,
  {
    activeText: string
    activeBorder: string
    badge: string
    icon: string
    glow: string
  }
> = {
  emerald: {
    activeText: 'text-emerald-600 dark:text-emerald-400',
    activeBorder: 'border-emerald-500 dark:border-emerald-400',
    badge: 'bg-emerald-500/10 text-emerald-600 dark:bg-emerald-400/10 dark:text-emerald-400',
    icon: 'border-emerald-500/20 bg-emerald-500/5 text-emerald-500',
    glow: 'from-emerald-500/20 to-emerald-500/0',
  },
  amber: {
    activeText: 'text-amber-600 dark:text-amber-400',
    activeBorder: 'border-amber-500 dark:border-amber-400',
    badge: 'bg-amber-500/10 text-amber-600 dark:bg-amber-400/10 dark:text-amber-400',
    icon: 'border-amber-500/20 bg-amber-500/5 text-amber-500',
    glow: 'from-amber-500/25 to-amber-500/0',
  },
  blue: {
    activeText: 'text-blue-600 dark:text-blue-400',
    activeBorder: 'border-blue-500 dark:border-blue-400',
    badge: 'bg-blue-500/10 text-blue-600 dark:bg-blue-400/10 dark:text-blue-400',
    icon: 'border-blue-500/20 bg-blue-500/5 text-blue-500',
    glow: 'from-blue-500/20 to-blue-500/0',
  },
  violet: {
    activeText: 'text-violet-600 dark:text-violet-400',
    activeBorder: 'border-violet-500 dark:border-violet-400',
    badge: 'bg-violet-500/10 text-violet-600 dark:bg-violet-400/10 dark:text-violet-400',
    icon: 'border-violet-500/20 bg-violet-500/5 text-violet-500',
    glow: 'from-violet-500/20 to-violet-500/0',
  },
}

const CYCLE_INTERVAL = 4600
const TRANSITION_MS = 220
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
  const siteName = publicConfig.site_name || 'openwebservermanager'
  const githubUrl = publicConfig.github_url || 'https://github.com/weige2008/openwebservermanager'
  const copyright = publicConfig.copyright || 'Copyright (c) 2026 weige2008. All rights reserved.'

  return (
    <div className='min-h-svh overflow-x-clip bg-background text-foreground'>
      <PublicHeader authenticated={authenticated} />
      <main className='bg-background text-foreground w-full'>
        <HeroSection copy={copy} entryText={entryText} entryTo={entryTo} siteName={siteName} />
        <StatsStrip copy={copy} />
        <FeatureBento copy={copy} />
        <ConnectionWorkspace copy={copy} entryText={entryText} entryTo={entryTo} siteName={siteName} />
        <SecurityAndWorkflow copy={copy} />
        <CtaSection authenticated={authenticated} copy={copy} entryText={entryText} entryTo={entryTo} />
      </main>
      <PublicFooter siteName={siteName} entryTo={entryTo} entryText={entryText} copy={copy} githubUrl={githubUrl} copyright={copyright} />
    </div>
  )
}

function HeroSection(props: { copy: HomeCopy; entryTo: string; entryText: string; siteName: string }) {
  const { copy, entryText, entryTo, siteName } = props

  return (
    <section className='relative z-10 overflow-hidden px-6 pt-24 pb-16 md:pt-32 md:pb-24 lg:pt-36 lg:pb-28'>
      <div
        aria-hidden
        className='pointer-events-none absolute inset-0 -z-10 opacity-25 dark:opacity-[0.12]'
        style={{
          background: [
            'radial-gradient(ellipse 60% 50% at 20% 20%, oklch(0.72 0.18 250 / 80%) 0%, transparent 70%)',
            'radial-gradient(ellipse 50% 40% at 80% 15%, oklch(0.65 0.15 200 / 60%) 0%, transparent 70%)',
            'radial-gradient(ellipse 40% 35% at 40% 80%, oklch(0.70 0.12 280 / 40%) 0%, transparent 70%)',
          ].join(', '),
        }}
      />
      <div
        aria-hidden
        className='absolute inset-0 -z-10 bg-[linear-gradient(to_right,var(--border)_1px,transparent_1px),linear-gradient(to_bottom,var(--border)_1px,transparent_1px)] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_30%,black_20%,transparent_100%)] bg-[size:4rem_4rem] opacity-[0.08]'
      />

      <div className='mx-auto grid max-w-6xl grid-cols-1 items-start gap-12 lg:grid-cols-12 lg:gap-8'>
        <div className='flex flex-col items-start text-left lg:col-span-6'>
          <div
            className='landing-animate-fade-up mb-5 inline-flex max-w-full items-center gap-1.5 rounded-full border border-blue-500/20 bg-blue-500/5 px-3 py-1.5 text-[11px] font-medium text-blue-600 opacity-0 shadow-xs dark:border-blue-400/20 dark:bg-blue-400/5 dark:text-blue-400'
            style={{ animationDelay: '0ms' }}
          >
            <span className='relative flex size-1.5 shrink-0'>
              <span className='absolute inline-flex h-full w-full animate-ping rounded-full bg-blue-400 opacity-75' />
              <span className='relative inline-flex size-1.5 rounded-full bg-blue-500 dark:bg-blue-400' />
            </span>
            <span className='truncate'>{copy.badge}</span>
          </div>

          <h1
            className='landing-animate-fade-up text-[clamp(2.25rem,4.5vw,3.25rem)] leading-[1.15] font-bold tracking-tight opacity-0'
            style={{ animationDelay: '60ms' }}
          >
            {siteName}
            <br />
            <span className='bg-gradient-to-r from-blue-400 via-violet-400 to-purple-500 bg-clip-text text-transparent'>
              {copy.connectionsTitle}
            </span>
          </h1>
          <p
            className='landing-animate-fade-up text-muted-foreground/80 mt-5 max-w-xl text-base leading-relaxed opacity-0 md:text-[15px]'
            style={{ animationDelay: '120ms' }}
          >
            {copy.heroBody}
          </p>

          <div
            className='landing-animate-fade-up mt-8 flex flex-wrap items-center gap-3 opacity-0'
            style={{ animationDelay: '180ms' }}
          >
            <Link to={entryTo} className={cn(buttonVariants({ variant: 'primary', size: 'lg' }), 'group h-11 rounded-lg px-5 text-sm font-medium')}>
              {entryText}
              <ArrowRight className='ml-1.5 size-4 transition-transform duration-200 group-hover:translate-x-0.5' />
            </Link>
            <Button
              type='button'
              variant='outline'
              className='border-border/50 hover:border-border hover:bg-muted/50 h-11 rounded-lg px-5 text-sm font-medium'
              onClick={() => document.querySelector('#product')?.scrollIntoView({ behavior: 'smooth' })}
            >
              {copy.viewProduct}
            </Button>
          </div>

          <div
            className='landing-animate-fade-up mt-10 w-full max-w-xl opacity-0'
            style={{ animationDelay: '240ms' }}
          >
            <div className='mb-4 flex flex-col gap-1'>
              <span className='text-muted-foreground/50 text-[10px] font-bold tracking-[0.15em] uppercase'>Supported Workspace</span>
              <p className='text-muted-foreground/60 text-xs leading-relaxed'>{copy.connectionsBody}</p>
            </div>
            <div className='flex flex-wrap items-center gap-3'>
              {copy.highlights.map((item, index) => (
                <div
                  key={item}
                  className={cn(
                    'group border-border/40 bg-muted/15 text-foreground/80 hover:border-border hover:bg-muted/30 hover:text-foreground flex cursor-default items-center gap-2.5 rounded-full border px-5 py-2.5 text-sm font-medium shadow-[0_1px_2.5px_rgba(0,0,0,0.01)] backdrop-blur-xs transition-all duration-300 hover:scale-[1.02]',
                    index === 0 && 'border-blue-500/20 bg-blue-500/5 text-blue-600 dark:text-blue-400'
                  )}
                >
                  <span className={cn('size-2 rounded-full', index === 2 ? 'bg-violet-500' : index === 3 ? 'bg-amber-500' : 'bg-blue-500')} />
                  <span>{item}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div
          className='landing-animate-fade-up flex w-full justify-center opacity-0 lg:col-span-6'
          style={{ animationDelay: '320ms' }}
        >
          <ServerProtocolDemo copy={copy} />
        </div>
      </div>
    </section>
  )
}

function ServerProtocolDemo({ copy }: { copy: HomeCopy }) {
  const demos: DemoConfig[] = [
    {
      id: 'ssh',
      label: 'SSH',
      method: 'SSH',
      endpoint: 'wss://openwebservermanager/connections/ssh/{session}/ws',
      accent: 'emerald',
      status: 'pty attached',
      latency: 28,
      rows: [
        { kind: 'command', text: '$ ssh ubuntu@10.18.12.24' },
        { kind: 'muted', text: copy.preview.terminalWelcome },
        { kind: 'command', text: '$ systemctl status app' },
        { kind: 'success', text: copy.preview.terminalStatus },
        { kind: 'key', text: 'resize: cols=142 rows=38' },
      ],
      metrics: [
        ['auth', 'key'],
        ['shell', 'bash'],
        ['stream', 'ws'],
      ],
    },
    {
      id: 'rdp',
      label: 'RDP',
      method: 'RDP',
      endpoint: 'wss://openwebservermanager/connections/rdp/{session}/tunnel',
      accent: 'blue',
      status: 'guacamole tunnel',
      latency: 34,
      rows: [
        { kind: 'command', text: 'select protocol: rdp' },
        { kind: 'key', text: 'hostname: windows-admin.internal' },
        { kind: 'key', text: 'resolution: 1920x1080 adaptive' },
        { kind: 'success', text: 'input: keyboard mouse clipboard' },
        { kind: 'muted', text: 'credentials remain server-side' },
      ],
      metrics: [
        ['desktop', '1080p'],
        ['clipboard', 'on'],
        ['files', 'on'],
      ],
    },
    {
      id: 'file',
      label: 'Files',
      method: 'FILE',
      endpoint: '/api/connections/{session}/transfer',
      accent: 'amber',
      status: 'transfer tracked',
      latency: 51,
      rows: [
        { kind: 'command', text: 'upload ./release.zip -> /tmp/release.zip' },
        { kind: 'success', text: '24 MB received' },
        { kind: 'command', text: 'download /var/log/app.log' },
        { kind: 'muted', text: 'audit: file transfer event stored' },
        { kind: 'warning', text: 'policy: authenticated session required' },
      ],
      metrics: [
        ['upload', '24 MB'],
        ['download', 'log'],
        ['audit', 'yes'],
      ],
    },
    {
      id: 'audit',
      label: 'Audit',
      method: 'AUDIT',
      endpoint: 'data/recordings/{session_id}/',
      accent: 'violet',
      status: 'recording indexed',
      latency: 19,
      rows: [
        { kind: 'command', text: 'session started -> active' },
        { kind: 'key', text: 'client_ip: 124.223.x.x' },
        { kind: 'success', text: 'recording stream persisted' },
        { kind: 'muted', text: 'metadata: size duration permission' },
        { kind: 'command', text: 'session closed -> completed' },
      ],
      metrics: [
        ['state', 'closed'],
        ['recording', 'raw'],
        ['viewer', 'admin'],
      ],
    },
  ]
  const [activeIndex, setActiveIndex] = useState(0)
  const [transitioning, setTransitioning] = useState(false)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    if (mq.matches) return

    intervalRef.current = setInterval(() => {
      setTransitioning(true)
      timeoutRef.current = setTimeout(() => {
        setActiveIndex((prev) => (prev + 1) % demos.length)
        setTransitioning(false)
      }, TRANSITION_MS)
    }, CYCLE_INTERVAL)

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
      if (timeoutRef.current) clearTimeout(timeoutRef.current)
    }
  }, [demos.length])

  const handleSelect = (index: number) => {
    if (index === activeIndex) return
    if (intervalRef.current) clearInterval(intervalRef.current)
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    setTransitioning(true)
    timeoutRef.current = setTimeout(() => {
      setActiveIndex(index)
      setTransitioning(false)
    }, TRANSITION_MS)
  }

  const demo = demos[activeIndex]
  const accent = ACCENT_CLASSES[demo.accent]

  return (
    <div className='mx-auto w-full max-w-2xl'>
      <div
        className={cn(
          'overflow-hidden rounded-2xl border backdrop-blur-sm',
          'border-border/60 bg-white/95 shadow-[0_20px_50px_-25px_rgba(15,23,42,0.18)]',
          'dark:border-white/[0.06] dark:bg-[#0b0f17]/95 dark:shadow-[0_20px_60px_-25px_rgba(0,0,0,0.7)]'
        )}
      >
        <div className='border-border/50 dark:border-white/[0.05] flex items-center gap-1 border-b px-2 sm:gap-1.5 sm:px-3'>
          {demos.map((item, index) => {
            const tone = ACCENT_CLASSES[item.accent]
            const isActive = index === activeIndex
            return (
              <button
                key={item.id}
                type='button'
                onClick={() => handleSelect(index)}
                className={cn(
                  'relative -mb-px flex items-center gap-1.5 border-b-2 px-2.5 py-2.5 text-[11px] font-medium tracking-wide transition-colors sm:px-3 sm:text-xs',
                  isActive ? `${tone.activeBorder} ${tone.activeText}` : 'border-transparent text-foreground/40 hover:text-foreground/70'
                )}
              >
                {item.label}
              </button>
            )
          })}
          <div className='ml-auto flex items-center gap-2 pr-2 sm:pr-3'>
            <span className='inline-block size-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.45)]' />
            <span className='font-mono text-[10px] tracking-wider text-foreground/40 uppercase'>online</span>
          </div>
        </div>

        <div className='border-border/40 dark:border-white/[0.04] flex items-center gap-2.5 border-b px-5 py-3'>
          <span className={cn('rounded-md px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wider', accent.badge)}>
            {demo.method}
          </span>
          <code className={cn('truncate font-mono text-[12.5px] text-foreground/75 transition-opacity duration-200', transitioning ? 'opacity-0' : 'opacity-100')}>
            {demo.endpoint}
          </code>
        </div>

        <div className='grid min-h-[400px] grid-rows-[minmax(0,1fr)_142px] font-mono text-[12.5px] leading-[1.55]'>
          <div className='relative overflow-hidden px-5 py-4'>
            <div className={cn('absolute -top-32 left-1/2 h-64 w-[120%] -translate-x-1/2 rounded-full bg-radial blur-3xl transition-all duration-500', accent.glow)} />
            <SectionLabel>Live session</SectionLabel>
            <div className={cn('relative mt-3 grid gap-2 transition-opacity duration-200', transitioning ? 'opacity-0' : 'opacity-100')}>
              {demo.rows.map((row, index) => (
                <CodeLine key={`${demo.id}-${index}`} kind={row.kind}>
                  {row.text}
                </CodeLine>
              ))}
            </div>
            <div className='relative mt-5 grid grid-cols-3 gap-2'>
              {demo.metrics.map(([label, value]) => (
                <div key={label} className='rounded-lg border border-border/40 bg-background/60 p-2 dark:bg-white/[0.02]'>
                  <div className='text-[10px] tracking-wider text-foreground/35 uppercase'>{label}</div>
                  <div className={cn('mt-1 truncate text-xs font-medium', accent.activeText)}>{value}</div>
                </div>
              ))}
            </div>
          </div>

          <div className='border-border/40 bg-muted/20 dark:border-white/[0.05] dark:bg-white/[0.015] border-t px-5 py-4'>
            <SectionLabel>Workspace state</SectionLabel>
            <div className={cn('mt-3 grid gap-3 transition-opacity duration-200 sm:grid-cols-[1fr_0.78fr]', transitioning ? 'opacity-0' : 'opacity-100')}>
              <div className='rounded-xl border border-border/50 bg-background/70 p-3'>
                <div className='mb-2 flex items-center justify-between text-[10px] tracking-wider text-foreground/35 uppercase'>
                  <span>{demo.status}</span>
                  <span>{demo.latency} ms</span>
                </div>
                <div className='flex items-end gap-1.5'>
                  {[38, 52, 44, 68, 58, 82, 61, 74, 46, 64].map((height, index) => (
                    <span
                      key={index}
                      className={cn('w-full rounded-sm bg-gradient-to-t', index % 3 === 0 ? 'from-blue-500/70 to-blue-300/20' : index % 3 === 1 ? 'from-violet-500/70 to-violet-300/20' : 'from-emerald-500/70 to-emerald-300/20')}
                      style={{ height }}
                    />
                  ))}
                </div>
              </div>
              <div className='rounded-xl border border-border/50 bg-background/70 p-3'>
                <div className='text-[10px] tracking-wider text-foreground/35 uppercase'>{copy.preview.workspace}</div>
                <div className='mt-2 grid gap-1.5'>
                  {copy.preview.servers.slice(0, 3).map((server, index) => (
                    <div key={server} className='flex min-w-0 items-center gap-2 text-[11px] text-foreground/70'>
                      <span className={cn('size-1.5 shrink-0 rounded-full', index === 1 ? 'bg-blue-500' : 'bg-emerald-500')} />
                      <span className='truncate'>{server}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className='border-border/40 bg-muted/30 dark:border-white/[0.05] dark:bg-white/[0.02] flex items-center justify-between border-t px-5 py-2.5'>
          <div className='flex items-center gap-3 text-[10px] tabular-nums text-foreground/40'>
            <span className='flex items-center gap-1'>
              <span className='font-mono'>{demo.latency}</span>
              <span className='tracking-wider uppercase'>ms</span>
            </span>
            <span className='size-1 rounded-full bg-foreground/15' />
            <span className='tracking-wider uppercase'>encrypted</span>
            <span className='size-1 rounded-full bg-foreground/15' />
            <span className='tracking-wider uppercase'>audit</span>
          </div>
          <span className='font-mono text-[10px] tracking-wider text-foreground/30 uppercase'>server-side credentials</span>
        </div>
      </div>
    </div>
  )
}

function StatsStrip({ copy }: { copy: HomeCopy }) {
  const stats = [
    { end: 2, suffix: '', label: 'SSH / RDP' },
    { end: copy.highlights.length, suffix: '', label: copy.highlights[1] ?? 'Browser access' },
    { end: copy.workflowSteps.length, suffix: '', label: copy.workflowEyebrow },
    { end: 23876, suffix: '', label: copy.deployTitle },
  ]

  return (
    <div className='border-border/40 bg-muted/10 relative z-10 border-y'>
      <div className='mx-auto max-w-6xl px-6 py-10 md:py-12'>
        <div className='grid grid-cols-2 gap-8 md:grid-cols-4 md:gap-12'>
          {stats.map((stat) => (
            <div key={stat.label} className='flex flex-col items-center text-center'>
              <span className='text-2xl font-bold tracking-tight md:text-3xl'>
                <Counter end={stat.end} suffix={stat.suffix} />
              </span>
              <span className='text-muted-foreground mt-1.5 text-xs'>{stat.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function FeatureBento({ copy }: { copy: HomeCopy }) {
  const features = copy.capabilities.slice(0, 4).map(([title, desc], index) => ({
    id: title,
    num: `0${index + 1}`,
    title,
    desc,
    span: index === 0 || index === 3 ? 'md:col-span-2' : 'md:col-span-1',
    icon: capabilityIcons[index],
    tone: index === 0 ? 'blue' : index === 1 ? 'emerald' : index === 2 ? 'violet' : 'amber',
  }))

  return (
    <section id='product' className='relative z-10 px-6 py-24 md:py-32'>
      <div className='mx-auto max-w-6xl'>
        <div className='landing-animate-fade-up mb-16 max-w-lg opacity-0'>
          <p className='text-muted-foreground mb-3 text-xs font-medium tracking-widest uppercase'>Core Features</p>
          <h2 className='text-2xl leading-tight font-bold tracking-tight md:text-3xl'>
            {copy.productTitle}
          </h2>
          <p className='text-muted-foreground/80 mt-4 text-sm leading-relaxed'>{copy.productBody}</p>
        </div>

        <div className='border-border/40 bg-border/40 grid gap-px overflow-hidden rounded-xl border md:grid-cols-3'>
          {features.map((feature, index) => (
            <article
              key={feature.id}
              className={cn(
                'landing-animate-scale-in bg-background group hover:bg-muted/20 p-7 opacity-0 transition-colors duration-300 md:p-8',
                feature.span
              )}
              style={{ animationDelay: `${index * 100}ms` }}
            >
              <div className='mb-3 flex items-center gap-3'>
                <span className='border-border/40 bg-muted text-muted-foreground flex size-7 items-center justify-center rounded-md border text-[10px] font-semibold tabular-nums'>
                  {feature.num}
                </span>
                <h3 className='text-sm font-semibold'>{feature.title}</h3>
              </div>
              <p className='text-muted-foreground text-sm leading-relaxed'>{feature.desc}</p>
              <FeatureVisual icon={feature.icon} tone={feature.tone as AccentTone} index={index} />
            </article>
          ))}
        </div>

        <div className='mt-12 grid grid-cols-1 gap-8 md:grid-cols-3 md:gap-12'>
          {copy.connectionCards.map(([title, desc], index) => {
            const Icon = connectionIcons[index]
            return (
              <div
                key={title}
                className='landing-animate-fade-up flex flex-col items-center text-center opacity-0'
                style={{ animationDelay: `${index * 100}ms` }}
              >
                <div className='text-muted-foreground border-border/50 bg-muted/30 mb-3 flex size-12 items-center justify-center rounded-xl border transition-colors'>
                  <Icon className='size-5' strokeWidth={1.5} />
                </div>
                <h3 className='mb-1.5 text-sm font-semibold'>{title}</h3>
                <p className='text-muted-foreground max-w-[260px] text-xs leading-relaxed'>{desc}</p>
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}

function FeatureVisual(props: { icon: LucideIcon; tone: AccentTone; index: number }) {
  const Icon = props.icon
  const tone = ACCENT_CLASSES[props.tone]
  if (props.index === 0) {
    return (
      <div className='mt-4 grid grid-cols-3 gap-2'>
        {['Linux', 'Windows', 'SSH', 'RDP', 'guacd', 'WebSocket'].map((name) => (
          <div key={name} className='border-border/30 bg-muted/20 text-muted-foreground flex items-center justify-center rounded-lg border px-3 py-2 text-xs transition-colors duration-300 hover:border-blue-500/30 hover:bg-blue-500/5'>
            {name}
          </div>
        ))}
      </div>
    )
  }

  if (props.index === 1) {
    return (
      <div className='mt-4 flex items-center justify-center'>
        <div className='relative'>
          <div className={cn('flex size-16 items-center justify-center rounded-2xl border', tone.icon)}>
            <Icon className='size-7' strokeWidth={1.5} />
          </div>
          <div className='absolute -top-1 -right-1 flex size-4 items-center justify-center rounded-full bg-emerald-500'>
            <CheckCircle2 className='size-3 text-white' strokeWidth={3} />
          </div>
        </div>
      </div>
    )
  }

  if (props.index === 2) {
    return (
      <div className='mt-4 space-y-2'>
        {['create', 'connect', 'close'].map((step, index) => (
          <div key={step} className='flex items-center gap-2'>
            <div className={cn('flex size-6 items-center justify-center rounded-full text-[10px] font-bold', index === 1 ? 'border border-blue-500/30 bg-blue-500/20 text-blue-500' : 'border-border/40 bg-muted text-muted-foreground border')}>
              {index + 1}
            </div>
            <div className='h-px flex-1 bg-border/40' />
            <span className='text-muted-foreground text-xs'>{step}</span>
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className='mt-4 flex items-center gap-3'>
      <div className='flex -space-x-2'>
        {['Go', 'SPA', 'DB', 'TLS'].map((name) => (
          <div key={name} className='border-background from-muted to-muted/60 text-muted-foreground flex size-8 items-center justify-center rounded-full border-2 bg-gradient-to-br text-[9px] font-bold'>
            {name}
          </div>
        ))}
      </div>
      <div className='text-muted-foreground flex items-center gap-1.5 text-xs'>
        <Code2 className='size-3.5 text-blue-500' />
        Cross-platform bundle
      </div>
    </div>
  )
}

function ConnectionWorkspace(props: { copy: HomeCopy; entryTo: string; entryText: string; siteName: string }) {
  const { copy, entryText, entryTo, siteName } = props

  return (
    <section id='connections' className='relative z-10 overflow-hidden px-6 py-24 md:py-32'>
      <div
        aria-hidden
        className='absolute inset-0 -z-10 opacity-20 dark:opacity-[0.08]'
        style={{
          background: [
            'radial-gradient(ellipse 50% 50% at 30% 50%, oklch(0.7 0.15 250 / 70%) 0%, transparent 70%)',
            'radial-gradient(ellipse 40% 40% at 70% 40%, oklch(0.65 0.12 200 / 50%) 0%, transparent 70%)',
          ].join(', '),
        }}
      />
      <div className='mx-auto grid max-w-6xl gap-10 lg:grid-cols-[0.82fr_1.18fr] lg:items-center'>
        <div className='landing-animate-fade-right opacity-0'>
          <p className='text-muted-foreground mb-3 text-xs font-medium tracking-widest uppercase'>Workspace</p>
          <h2 className='text-2xl leading-tight font-bold tracking-tight md:text-3xl'>
            {copy.connectionsTitle}
          </h2>
          <p className='text-muted-foreground/80 mt-5 max-w-xl text-sm leading-relaxed'>{copy.connectionsBody}</p>
          <Link to={entryTo} className={cn(buttonVariants({ variant: 'outline', size: 'lg' }), 'mt-8 h-11 rounded-lg px-5 text-sm font-medium')}>
            {entryText}
            <ChevronRight className='size-4' />
          </Link>
        </div>
        <GatewayCard copy={copy} siteName={siteName} />
      </div>
    </section>
  )
}

function GatewayCard({ copy, siteName }: { copy: HomeCopy; siteName: string }) {
  const features = ['SSH PTY', 'RDP Tunnel', 'Clipboard', 'File Transfer', 'Recording', 'Audit Log', 'Encrypted Keys', 'Local Data']

  return (
    <div className='glass-3 landing-animate-fade-left group border-border/50 dark:border-border/20 relative overflow-hidden rounded-4xl border p-8 opacity-0 shadow-2xl transition-all duration-500 sm:p-10 dark:shadow-[0_25px_80px_-15px_rgba(0,0,0,0.4)]'>
      <div className='absolute top-0 left-[10%] h-[2px] w-[80%] bg-gradient-to-r from-transparent via-amber-500/80 to-transparent' />
      <div className='absolute -top-32 left-1/2 h-64 w-[120%] -translate-x-1/2 rounded-full bg-radial from-amber-500/30 to-amber-500/0 blur-3xl transition-all duration-500 group-hover:opacity-100 dark:opacity-80' />

      <div className='relative'>
        <div className='mb-8 flex items-center justify-center gap-3'>
          <div className='flex size-12 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500/15 via-violet-500/10 to-amber-500/15 ring-1 ring-border/60'>
            <TerminalSquare className='size-6 text-blue-500' />
          </div>
          <h3 className='from-foreground to-foreground/70 bg-gradient-to-r bg-clip-text text-2xl font-bold text-transparent'>
            {siteName}
          </h3>
        </div>

        <div className='grid grid-cols-2 gap-3'>
          {features.map((feature, index) => (
            <div
              key={feature}
              className='glass-morphism group/item border-border/40 dark:border-border/20 relative overflow-hidden rounded-xl border px-4 py-3.5 text-center shadow-sm transition-all duration-300 hover:scale-[1.02] hover:border-amber-500/40 hover:shadow-md'
            >
              <div className={cn('absolute inset-0 bg-gradient-to-br transition-all duration-300', index % 3 === 0 ? 'from-blue-500/0 to-blue-500/0 group-hover/item:from-blue-500/10' : index % 3 === 1 ? 'from-violet-500/0 to-violet-500/0 group-hover/item:from-violet-500/10' : 'from-amber-500/0 to-amber-500/0 group-hover/item:from-amber-500/10')} />
              <span className='text-foreground/90 group-hover/item:text-foreground relative text-sm font-medium'>{feature}</span>
            </div>
          ))}
        </div>

        <div className='mt-6 grid grid-cols-3 gap-3'>
          <SceneMetric icon={FileUp} label={copy.preview.upload} value='24 MB' />
          <SceneMetric icon={Download} label={copy.preview.recording} value='00:18:42' />
          <SceneMetric icon={Network} label={copy.preview.latency} value='28 ms' />
        </div>
      </div>
    </div>
  )
}

function SecurityAndWorkflow({ copy }: { copy: HomeCopy }) {
  return (
    <section id='security' className='relative z-10 px-6 py-24 md:py-32'>
      <div className='mx-auto grid max-w-6xl gap-12 lg:grid-cols-[0.95fr_1.05fr]'>
        <div>
          <div className='landing-animate-fade-up max-w-xl opacity-0'>
            <p className='text-muted-foreground mb-3 text-xs font-medium tracking-widest uppercase'>Security</p>
            <h2 className='text-2xl leading-tight font-bold tracking-tight md:text-3xl'>{copy.securityTitle}</h2>
            <p className='text-muted-foreground/80 mt-5 text-sm leading-relaxed'>{copy.securityBody}</p>
          </div>
          <div className='mt-8 grid gap-3'>
            {copy.securityItems.map(([title, body], index) => (
              <SecurityRow key={title} icon={securityIcons[index]} title={title} body={body} index={index} />
            ))}
          </div>
        </div>

        <div>
          <div className='landing-animate-fade-up max-w-xl opacity-0' style={{ animationDelay: '120ms' }}>
            <p className='text-muted-foreground mb-3 text-xs font-medium tracking-widest uppercase'>{copy.workflowEyebrow}</p>
            <h2 className='text-2xl leading-tight font-bold tracking-tight md:text-3xl'>{copy.workflowTitle}</h2>
            <p className='text-muted-foreground/80 mt-5 text-sm leading-relaxed'>{copy.workflowBody}</p>
          </div>
          <div className='mt-8 grid gap-px overflow-hidden rounded-xl border border-border/40 bg-border/40 sm:grid-cols-2'>
            {copy.workflowSteps.map(([step, title, body], index) => (
              <WorkflowStep key={step} index={index} step={step} title={title} body={body} />
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}

function CtaSection(props: { authenticated: boolean; copy: HomeCopy; entryTo: string; entryText: string }) {
  const { authenticated, copy, entryText, entryTo } = props

  return (
    <section id='deploy' className='relative z-10 overflow-hidden px-6 py-24 md:py-32'>
      <div
        aria-hidden
        className='absolute inset-0 -z-10 opacity-20 dark:opacity-[0.08]'
        style={{
          background: [
            'radial-gradient(ellipse 50% 50% at 30% 50%, oklch(0.7 0.15 250 / 70%) 0%, transparent 70%)',
            'radial-gradient(ellipse 40% 40% at 70% 40%, oklch(0.65 0.12 200 / 50%) 0%, transparent 70%)',
          ].join(', '),
        }}
      />

      <div className='landing-animate-scale-in mx-auto max-w-2xl text-center opacity-0'>
        <h2 className='text-2xl leading-tight font-bold tracking-tight md:text-4xl'>
          {copy.deployTitle}
          <br />
          <span className='bg-gradient-to-r from-blue-400 via-violet-400 to-purple-500 bg-clip-text text-transparent'>
            {copy.openWorkspace}
          </span>
        </h2>
        <p className='text-muted-foreground/80 mx-auto mt-5 max-w-md text-sm leading-relaxed md:text-base'>{copy.deployBody}</p>
        <div className='mt-8 flex flex-wrap items-center justify-center gap-3'>
          <Link to={entryTo} className={cn(buttonVariants({ variant: 'primary' }), 'group h-10 rounded-lg px-4')}>
            {entryText}
            <ArrowRight className='ml-1 size-3.5 transition-transform duration-200 group-hover:translate-x-0.5' />
          </Link>
          {!authenticated ? (
            <Button
              type='button'
              variant='outline'
              className='border-border/50 hover:border-border hover:bg-muted/50 h-10 rounded-lg px-4'
              onClick={() => document.querySelector('#product')?.scrollIntoView({ behavior: 'smooth' })}
            >
              {copy.viewProduct}
            </Button>
          ) : null}
        </div>
      </div>
    </section>
  )
}

function Counter(props: { end: number; suffix?: string; prefix?: string; duration?: number }) {
  const { end, suffix = '', prefix = '', duration = 1600 } = props
  const ref = useRef<HTMLSpanElement>(null)
  const startedRef = useRef(false)

  const formatValue = useCallback((value: number) => Math.round(value).toLocaleString(), [])

  const animate = useCallback(() => {
    const el = ref.current
    if (!el) return
    const start = performance.now()
    const step = (now: number) => {
      const progress = Math.min((now - start) / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      el.textContent = `${prefix}${formatValue(eased * end)}${suffix}`
      if (progress < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [duration, end, formatValue, prefix, suffix])

  useEffect(() => {
    const el = ref.current
    if (!el) return

    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    if (mq.matches) {
      el.textContent = `${prefix}${formatValue(end)}${suffix}`
      return
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry?.isIntersecting && !startedRef.current) {
          startedRef.current = true
          animate()
          observer.unobserve(el)
        }
      },
      { threshold: 0.5 }
    )

    observer.observe(el)
    return () => observer.disconnect()
  }, [animate, end, formatValue, prefix, suffix])

  return (
    <span ref={ref} className='tabular-nums'>
      {prefix}0{suffix}
    </span>
  )
}

function SceneMetric({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: string }) {
  return (
    <div className='rounded-xl border border-border/50 bg-background/60 p-3'>
      <Icon className='mb-2 size-4 text-muted-foreground sm:mb-3' />
      <div className='truncate text-xs text-muted-foreground'>{label}</div>
      <div className='mt-1 truncate font-mono text-sm font-semibold'>{value}</div>
    </div>
  )
}

function SecurityRow({ icon: Icon, title, body, index }: { icon: LucideIcon; title: string; body: string; index: number }) {
  return (
    <article
      className='landing-animate-fade-up grid grid-cols-[2.25rem_1fr] gap-4 rounded-xl border border-border bg-card/70 p-5 opacity-0 shadow-sm backdrop-blur-sm'
      style={{ animationDelay: `${index * 90}ms` }}
    >
      <span className='grid size-9 place-items-center rounded-lg bg-gradient-to-br from-blue-500/10 via-violet-500/10 to-amber-500/10 text-muted-foreground ring-1 ring-border/50'>
        <Icon className='size-4' />
      </span>
      <div>
        <h3 className='text-sm font-semibold'>{title}</h3>
        <p className='mt-1 text-sm leading-6 text-muted-foreground'>{body}</p>
      </div>
    </article>
  )
}

function WorkflowStep({ index, step, title, body }: { index: number; step: string; title: string; body: string }) {
  return (
    <article
      className='landing-animate-scale-in bg-background p-5 opacity-0 transition-colors duration-300 hover:bg-muted/20'
      style={{ animationDelay: `${index * 90}ms` }}
    >
      <span className='font-mono text-xs font-semibold text-muted-foreground'>{step}</span>
      <h3 className='mt-3 text-sm font-semibold'>{title}</h3>
      <p className='mt-2 text-sm leading-6 text-muted-foreground'>{body}</p>
    </article>
  )
}

function SectionLabel(props: { children: ReactNode }) {
  return (
    <span className='font-sans text-[10px] font-semibold tracking-[0.18em] text-foreground/30 uppercase'>
      {props.children}
    </span>
  )
}

function CodeLine(props: { children: ReactNode; kind: DemoConfig['rows'][number]['kind'] }) {
  const className = {
    command: 'text-emerald-600 dark:text-emerald-400',
    muted: 'text-foreground/55',
    success: 'text-success',
    warning: 'text-warning',
    key: 'text-sky-700 dark:text-sky-300',
  }[props.kind]

  return <div className={cn('break-words whitespace-pre-wrap', className)}>{props.children}</div>
}

function PublicFooter({
  siteName,
  entryTo,
  entryText,
  copy,
  githubUrl,
  copyright,
}: {
  siteName: string
  entryTo: string
  entryText: string
  copy: HomeCopy
  githubUrl: string
  copyright: string
}) {
  const { t } = useTranslation()

  return (
    <footer className='border-t border-border bg-background'>
      <div className='mx-auto grid w-[min(72rem,calc(100%-2rem))] gap-8 py-10 md:grid-cols-[1.2fr_0.8fr_0.8fr]'>
        <div>
          <div className='inline-flex items-center gap-2 text-sm font-semibold'>
            <BrandLogo className='size-7' title={siteName} />
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
            [t('about'), '/about'],
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
        <span>{copyright}</span>
        <span className='flex flex-wrap items-center gap-3'>
          <a href={githubUrl} target='_blank' rel='noreferrer' className='transition-colors hover:text-foreground'>
            {t('github')}
          </a>
          <span>{copy.footerBuilt}</span>
        </span>
      </div>
    </footer>
  )
}

function FooterColumn({ title, links }: { title: string; links: Array<[string | undefined, string]> }) {
  return (
    <nav>
      <h3 className='text-xs font-semibold tracking-[0.12em] text-muted-foreground uppercase'>{title}</h3>
      <div className='mt-4 grid gap-2'>
        {links.map(([label, href]) => (
          <a key={href} href={resolvePublicHref(href)} className='text-sm text-muted-foreground transition-colors hover:text-foreground'>
            {label}
          </a>
        ))}
      </div>
    </nav>
  )
}
