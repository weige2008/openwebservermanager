import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

import i18n from '@/i18n/config'
import { normalizeInterfaceLanguage } from '@/i18n/languages'
import type { Credential, CredentialType, ManagedServer, Protocol, ServerOS, SessionStatus } from '@/types'

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

export function credentialProtocol(value: CredentialType): Protocol {
  if (value === 'rdp_password') return 'rdp'
  if (value === 'vnc_password') return 'vnc'
  if (value === 'database_password') return 'database'
  return 'ssh'
}

export function statusLabel(value: SessionStatus): string {
  return i18n.t(`statusLabels.${value}`, { defaultValue: value })
}

export function serverProtocol(server: ManagedServer): Protocol {
  return server.os === 'windows' ? 'rdp' : 'ssh'
}

export function serverSupportsProtocol(server: ManagedServer | undefined, protocol: Protocol): boolean {
  if (!server) return false
  return serverProtocol(server) === protocol
}

export function credentialSupportsServer(credential: Credential, server: ManagedServer | undefined): boolean {
  if (!server) return false
  if (credential.server_id && credential.server_id !== server.id) return false
  return credentialProtocol(credential.type) === serverProtocol(server)
}

export function credentialsForServer(credentials: Credential[], server: ManagedServer | undefined): Credential[] {
  if (!server) return []
  return credentials
    .filter((credential) => credentialSupportsServer(credential, server))
    .sort((left, right) => Number(Boolean(right.server_id)) - Number(Boolean(left.server_id)) || left.name.localeCompare(right.name))
}

export function routeToView(pathname: string) {
  if (pathname.endsWith('/servers')) return 'servers'
  if (pathname.endsWith('/credentials')) return 'servers'
  if (pathname.endsWith('/sessions')) return 'sessions'
  if (pathname.endsWith('/audit')) return 'audit'
  return 'overview'
}
