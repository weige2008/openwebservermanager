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

export function canViewPlatformPage(role: string | undefined, page: PlatformPageConfig, menuPermissions: string[] = []) {
  if (isAdminRole(role)) return true
  if (isAuditorRole(role)) {
    return page.collection.endsWith('_logs') ||
      page.collection === 'access_stats' ||
      page.collection === 'online_sessions' ||
      page.collection === 'offline_sessions' ||
      page.collection === 'system_monitoring'
  }
  if (normalizeRole(role) === 'custom') {
    return menuPermissionAllows(menuPermissions, page)
  }
  return false
}

export function menuPermissionAllows(menuPermissions: string[], page: PlatformPageConfig) {
  if (!menuPermissions.length) return false
  const candidates = new Set([
    '*',
    'admin:*',
    page.collection,
    page.route,
    `${page.collection}:read`,
    `${page.collection}:*`,
    page.kind ? `${page.kind}:read` : '',
    page.kind ? `${page.kind}:*` : '',
  ].filter(Boolean))
  return menuPermissions.some((permission) => {
    const value = permission.trim()
    if (candidates.has(value)) return true
    if (value.endsWith('*')) {
      const prefix = value.slice(0, -1)
      return page.collection.startsWith(prefix) || page.route.startsWith(prefix)
    }
    return false
  })
}
