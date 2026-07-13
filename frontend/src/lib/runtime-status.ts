import type { GuacdRuntimeStatus } from '@/types'

export function isGuacdReady(status?: GuacdRuntimeStatus) {
  return status?.status === 'running'
}
