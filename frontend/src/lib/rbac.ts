import type { PlatformPageConfig } from './platform'

export type RoleKind = 'super_admin' | 'admin' | 'auditor' | 'user' | 'custom'

export function normalizeRole(role?: string): RoleKind {
  const value = (role || '').trim().toLowerCase().replace(/[-\s]+/g, '_')
  if (['super_admin', 'superadmin', 'root', 'owner', '超级管理员'].includes(value)) return 'super_admin'
  if (['admin', 'administrator', '管理员'].includes(value)) return 'admin'
  if (['auditor', 'audit', '审计员'].includes(value)) return 'auditor'
  if (!value || ['user', 'member', '普通用户'].includes(value)) return 'user'
  return 'custom'
}

export function isAdminRole(role?: string) {
  const kind = normalizeRole(role)
  return kind === 'super_admin' || kind === 'admin'
}

export function isAuditorRole(role?: string) {
  return normalizeRole(role) === 'auditor'
}

export function canViewPlatformPage(role: string | undefined, page: PlatformPageConfig) {
  if (isAdminRole(role)) return true
  if (isAuditorRole(role)) {
    return page.collection.endsWith('_logs') ||
      page.collection === 'access_stats' ||
      page.collection === 'online_sessions' ||
      page.collection === 'offline_sessions' ||
      page.collection === 'system_monitoring'
  }
  return false
}
