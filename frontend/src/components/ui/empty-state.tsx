import { FadeIn } from '@/components/page-transition'

export function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <FadeIn>
      <div className='grid min-h-40 place-items-center gap-2 px-6 py-8 text-center'>
        <strong>{title}</strong>
        <p className='max-w-md text-sm text-muted-foreground'>{body}</p>
      </div>
    </FadeIn>
  )
}
