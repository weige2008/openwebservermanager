import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

import type { CredentialType, ServerOS, SessionStatus } from '@/types'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(value?: string): string {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleString('zh-CN', { hour12: false })
}

export function osLabel(value?: ServerOS | string): string {
  if (value === 'windows') return 'Windows'
  if (value === 'linux') return 'Linux'
  return value || '-'
}

export function credentialLabel(value: CredentialType): string {
  return {
    ssh_password: 'SSH 密码',
    ssh_key: 'SSH 私钥',
    rdp_password: 'RDP 密码',
  }[value]
}

export function statusLabel(value: SessionStatus): string {
  return {
    pending: '等待中',
    active: '活跃',
    closed: '已关闭',
    failed: '失败',
  }[value] || value
}

export function routeToView(pathname: string) {
  if (pathname.endsWith('/servers')) return 'servers'
  if (pathname.endsWith('/credentials')) return 'credentials'
  if (pathname.endsWith('/sessions')) return 'sessions'
  if (pathname.endsWith('/audit')) return 'audit'
  return 'overview'
}
