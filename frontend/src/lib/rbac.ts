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

export function canUseAPI(role: string | undefined, apiPermissions: string[] = [], method: string, path: string) {
  const normalizedMethod = method.trim().toUpperCase()
  const normalizedPath = trimRightSlash(path)
  if (isAdminRole(role)) return true
  if (isAuditorRole(role)) return auditorCanUseAPI(normalizedMethod, normalizedPath)
  if (normalizeRole(role) !== 'custom') return false
  return apiPermissions.some((permission) => permissionMatchesAPI(permission, normalizedMethod, normalizedPath))
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

function auditorCanUseAPI(method: string, path: string) {
  if (method !== 'GET') return false
  return path === '/api/system/monitoring' ||
    path === '/api/bootstrap' ||
    path === '/api/audit' ||
    path.startsWith('/api/admin/audit/')
}

function permissionMatchesAPI(permission: string, method: string, path: string) {
  const value = permission.trim()
  if (!value) return false
  if (value === 'admin:*' || value === '* /api/*' || value === '*') return true
  if (value === 'audit:read' && method === 'GET' && path.startsWith('/api/admin/audit/')) return true
  const parts = value.split(/\s+/)
  if (parts.length === 1) {
    return pathMatches(parts[0], path) || (method === 'GET' && collectionDetailPathMatches(parts[0], path))
  }
  if (parts[0] !== '*' && parts[0].toUpperCase() !== method) return false
  return pathMatches(parts[1], path) || (method === 'GET' && collectionDetailPathMatches(parts[1], path))
}

function pathMatches(pattern: string, path: string) {
  const normalizedPattern = trimRightSlash(pattern)
  const normalizedPath = trimRightSlash(path)
  if (normalizedPattern === normalizedPath) return true
  if (normalizedPattern.endsWith('/*')) {
    return normalizedPath.startsWith(`${normalizedPattern.slice(0, -2)}/`)
  }
  if (normalizedPattern.endsWith('*')) {
    return normalizedPath.startsWith(normalizedPattern.slice(0, -1))
  }
  return false
}

function collectionDetailPathMatches(pattern: string, path: string) {
  const normalizedPattern = trimRightSlash(pattern)
  const normalizedPath = trimRightSlash(path)
  if (!normalizedPattern || normalizedPattern.includes('*') || normalizedPattern === normalizedPath) return false
  const prefix = `${normalizedPattern}/`
  if (!normalizedPath.startsWith(prefix)) return false
  const tail = normalizedPath.slice(prefix.length)
  return Boolean(tail) && !tail.includes('/')
}

function trimRightSlash(value: string) {
  return value.replace(/\/+$/, '') || '/'
}
