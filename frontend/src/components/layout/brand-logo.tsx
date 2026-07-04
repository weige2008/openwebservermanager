import { cn } from '@/lib/utils'

export function BrandLogo({ className, title = 'openwebservermanager' }: { className?: string; title?: string }) {
  return (
    <svg
      viewBox='0 0 40 40'
      role='img'
      aria-label={title}
      className={cn('size-6 shrink-0', className)}
      fill='none'
      xmlns='http://www.w3.org/2000/svg'
    >
      <defs>
        <linearGradient id='openwebservermanager-logo-bg' x1='5' y1='3' x2='35' y2='37' gradientUnits='userSpaceOnUse'>
          <stop stopColor='#38BDF8' />
          <stop offset='0.48' stopColor='#6366F1' />
          <stop offset='1' stopColor='#A855F7' />
        </linearGradient>
        <linearGradient id='openwebservermanager-logo-line' x1='11' y1='11' x2='30' y2='30' gradientUnits='userSpaceOnUse'>
          <stop stopColor='#FFFFFF' />
          <stop offset='1' stopColor='#DBEAFE' />
        </linearGradient>
      </defs>
      <rect width='40' height='40' rx='12' fill='url(#openwebservermanager-logo-bg)' />
      <path d='M11.5 14.2C11.5 12.98 12.48 12 13.7 12h12.6c1.22 0 2.2.98 2.2 2.2v11.6c0 1.22-.98 2.2-2.2 2.2H13.7c-1.22 0-2.2-.98-2.2-2.2V14.2Z' fill='white' fillOpacity='0.18' />
      <path d='M15 16h10M15 20h10M15 24h6.5' stroke='url(#openwebservermanager-logo-line)' strokeWidth='2' strokeLinecap='round' />
      <path d='M24.4 23.1 28 20l-3.6-3.1' stroke='white' strokeWidth='2.1' strokeLinecap='round' strokeLinejoin='round' />
      <circle cx='13.7' cy='32.2' r='2.2' fill='#FDE68A' />
      <circle cx='30.4' cy='31.6' r='2.4' fill='#86EFAC' />
      <path d='M15.9 32.1h6.4c2.1 0 3.3-.7 4.4-2.1' stroke='white' strokeOpacity='0.72' strokeWidth='1.6' strokeLinecap='round' />
      <path d='M8.4 10.5 6.8 8.9M31.6 8.6l1.7-1.7M33.7 14.4h2.1' stroke='white' strokeOpacity='0.5' strokeWidth='1.8' strokeLinecap='round' />
    </svg>
  )
}
