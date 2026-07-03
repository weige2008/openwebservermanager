import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

import i18n from '@/i18n/config'
import { normalizeInterfaceLanguage } from '@/i18n/languages'
import type { CredentialType, ServerOS, SessionStatus } from '@/types'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(value?: string): string {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'

  const locale = {
    zh: 'zh-CN',
    'zh-TW': 'zh-TW',
    en: 'en-US',
    fr: 'fr-FR',
    ru: 'ru-RU',
    ja: 'ja-JP',
    vi: 'vi-VN',
  }[normalizeInterfaceLanguage(i18n.language)]

  return date.toLocaleString(locale, { hour12: false })
}

export function osLabel(value?: ServerOS | string): string {
  if (value === 'windows') return 'Windows'
  if (value === 'linux') return 'Linux'
  return value || '-'
}

export function credentialLabel(value: CredentialType): string {
  return i18n.t(`credentialTypes.${value}`, { defaultValue: value })
}

export function statusLabel(value: SessionStatus): string {
  return i18n.t(`statusLabels.${value}`, { defaultValue: value })
}

export function routeToView(pathname: string) {
  if (pathname.endsWith('/servers')) return 'servers'
  if (pathname.endsWith('/credentials')) return 'credentials'
  if (pathname.endsWith('/sessions')) return 'sessions'
  if (pathname.endsWith('/audit')) return 'audit'
  return 'overview'
}
