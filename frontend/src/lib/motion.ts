import type { Transition } from 'motion/react'

const EASE_OUT_CUBIC = [0.33, 1, 0.68, 1] as const

export const MOTION_TRANSITION: Record<'default' | 'fast', Transition> = {
  default: { duration: 0.25, ease: EASE_OUT_CUBIC },
  fast: { duration: 0.15, ease: EASE_OUT_CUBIC },
}

export const MOTION_VARIANTS = {
  pageEnter: {
    initial: { opacity: 0, y: 8, filter: 'blur(4px)' },
    animate: { opacity: 1, y: 0, filter: 'blur(0px)' },
    exit: { opacity: 0, y: -4, filter: 'blur(2px)' },
  },
} as const
