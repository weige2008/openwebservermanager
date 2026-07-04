import { useRouterState } from '@tanstack/react-router'
import { motion, useReducedMotion } from 'motion/react'
import type { ReactNode } from 'react'

import { MOTION_TRANSITION, MOTION_VARIANTS } from '@/lib/motion'

interface PageTransitionProps {
  children: ReactNode
  className?: string
}

export function PageTransition(props: PageTransitionProps) {
  const shouldReduce = useReducedMotion()

  if (shouldReduce) {
    return <div className={props.className}>{props.children}</div>
  }

  return (
    <motion.div
      initial={MOTION_VARIANTS.pageEnter.initial}
      animate={MOTION_VARIANTS.pageEnter.animate}
      transition={MOTION_TRANSITION.default}
      className={props.className}
    >
      {props.children}
    </motion.div>
  )
}

export function ConsolePageTransition(props: PageTransitionProps) {
  const shouldReduce = useReducedMotion()
  const routeKey = useRouterState({
    select: (state) => state.matches[state.matches.length - 1]?.routeId ?? state.location.pathname,
  })

  if (shouldReduce) {
    return <div className={props.className}>{props.children}</div>
  }

  return (
    <motion.div
      key={routeKey}
      initial={MOTION_VARIANTS.pageEnter.initial}
      animate={MOTION_VARIANTS.pageEnter.animate}
      transition={MOTION_TRANSITION.fast}
      className={props.className}
    >
      {props.children}
    </motion.div>
  )
}
