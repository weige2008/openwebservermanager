import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'

import ts from 'typescript'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const sourcePath = path.resolve(__dirname, '../src/lib/rbac.ts')
const source = await fs.readFile(sourcePath, 'utf8')
const transpiled = ts.transpileModule(source, {
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ES2022,
    importsNotUsedAsValues: ts.ImportsNotUsedAsValues.Remove,
  },
})

const tempPath = path.join(os.tmpdir(), `openwebservermanager-rbac-${process.pid}-${Date.now()}.mjs`)
await fs.writeFile(tempPath, transpiled.outputText, 'utf8')

try {
  const { canUseAPI } = await import(pathToFileURL(tempPath).href)
  const cases = [
    ['admin can run storage writes', true, canUseAPI('admin', [], 'POST', '/api/admin/storages/s1/files-write')],
    ['auditor can read audit recordings', true, canUseAPI('auditor', [], 'GET', '/api/admin/audit/offline-sessions/s1/recording')],
    ['auditor cannot disconnect online sessions', false, canUseAPI('auditor', [], 'POST', '/api/admin/audit/online-sessions/s1/disconnect')],
    ['user cannot use admin APIs', false, canUseAPI('user', [], 'GET', '/api/admin/storages')],
    ['collection read allows one item detail', true, canUseAPI('custom', ['GET /api/admin/storages'], 'GET', '/api/admin/storages/s1')],
    ['collection read does not allow storage file actions', false, canUseAPI('custom', ['GET /api/admin/storages'], 'GET', '/api/admin/storages/s1/files')],
    ['storage wildcard read allows file download', true, canUseAPI('custom', ['GET /api/admin/storages/*'], 'GET', '/api/admin/storages/s1/files-download')],
    ['storage wildcard read does not allow upload', false, canUseAPI('custom', ['GET /api/admin/storages/*'], 'POST', '/api/admin/storages/s1/files-upload')],
    ['storage wildcard write allows upload', true, canUseAPI('custom', ['POST /api/admin/storages/*'], 'POST', '/api/admin/storages/s1/files-upload')],
    ['method wildcard allows storage delete', true, canUseAPI('custom', ['* /api/admin/storages/*'], 'DELETE', '/api/admin/storages/s1/files')],
    ['backup list permission allows list only', true, canUseAPI('custom', ['GET /api/admin/backups'], 'GET', '/api/admin/backups')],
    ['backup list permission does not allow download', false, canUseAPI('custom', ['GET /api/admin/backups'], 'GET', '/api/admin/backups/openweb.zip/download')],
    ['backup wildcard read allows download', true, canUseAPI('custom', ['GET /api/admin/backups/*'], 'GET', '/api/admin/backups/openweb.zip/download')],
    ['backup create permission does not allow restore', false, canUseAPI('custom', ['POST /api/admin/backups'], 'POST', '/api/admin/backups/restore')],
    ['backup restore permission allows restore', true, canUseAPI('custom', ['POST /api/admin/backups/restore'], 'POST', '/api/admin/backups/restore')],
    ['backup delete wildcard allows delete', true, canUseAPI('custom', ['DELETE /api/admin/backups/*'], 'DELETE', '/api/admin/backups/openweb.zip')],
    ['tool runner requires POST permission', true, canUseAPI('custom', ['POST /api/tools/ping'], 'POST', '/api/tools/ping')],
    ['tool runner rejects GET permission', false, canUseAPI('custom', ['GET /api/tools/ping'], 'POST', '/api/tools/ping')],
    ['monitoring read allows auditor', true, canUseAPI('auditor', [], 'GET', '/api/system/monitoring')],
    ['monitoring read allows custom GET permission', true, canUseAPI('custom', ['GET /api/system/monitoring'], 'GET', '/api/system/monitoring')],
    ['access stats allows audit read', true, canUseAPI('custom', ['audit:read'], 'GET', '/api/admin/audit/access-stats')],
    ['access stats rejects non-audit collection read', false, canUseAPI('custom', ['GET /api/admin/access-stats'], 'GET', '/api/admin/audit/access-stats')],
    ['system settings read allows setting detail', true, canUseAPI('custom', ['GET /api/admin/system-settings'], 'GET', '/api/admin/system-settings/s1')],
    ['system settings read does not allow OIDC test', false, canUseAPI('custom', ['GET /api/admin/system-settings'], 'POST', '/api/admin/system-settings/oidc/test')],
    ['system settings create does not allow existing setting patch', false, canUseAPI('custom', ['POST /api/admin/system-settings'], 'PATCH', '/api/admin/system-settings/s1')],
    ['system settings wildcard patch allows existing setting update', true, canUseAPI('custom', ['PATCH /api/admin/system-settings/*'], 'PATCH', '/api/admin/system-settings/s1')],
    ['SMTP test requires its explicit API permission', true, canUseAPI('custom', ['POST /api/admin/system-settings/smtp/test'], 'POST', '/api/admin/system-settings/smtp/test')],
    ['login policies read allows detail only', true, canUseAPI('custom', ['GET /api/admin/login-policies'], 'GET', '/api/admin/login-policies/p1')],
    ['login policies read rejects toggle', false, canUseAPI('custom', ['GET /api/admin/login-policies'], 'PATCH', '/api/admin/login-policies/p1')],
    ['login lock read rejects unlock', false, canUseAPI('custom', ['GET /api/admin/login-locked'], 'DELETE', '/api/admin/login-locked/l1')],
    ['login lock wildcard delete allows unlock', true, canUseAPI('custom', ['DELETE /api/admin/login-locked/*'], 'DELETE', '/api/admin/login-locked/l1')],
    ['license read does not allow update', false, canUseAPI('custom', ['GET /api/admin/license'], 'PUT', '/api/admin/license')],
    ['license put allows local license save', true, canUseAPI('custom', ['PUT /api/admin/license'], 'PUT', '/api/admin/license')],
    ['proxy services read does not allow save', false, canUseAPI('custom', ['GET /api/admin/proxy-services'], 'POST', '/api/admin/proxy-services')],
    ['proxy services post allows save', true, canUseAPI('custom', ['POST /api/admin/proxy-services'], 'POST', '/api/admin/proxy-services')],
    ['certificate ACME permission does not imply DNS provider read', false, canUseAPI('custom', ['POST /api/admin/certificates/acme'], 'GET', '/api/admin/certificates/dns-providers')],
    ['certificate DNS provider read allows provider list', true, canUseAPI('custom', ['GET /api/admin/certificates/dns-providers'], 'GET', '/api/admin/certificates/dns-providers')],
    ['certificate collection read does not allow certificate logs', false, canUseAPI('custom', ['GET /api/admin/certificates'], 'GET', '/api/admin/certificates/c1/logs')],
    ['certificate wildcard read allows certificate logs', true, canUseAPI('custom', ['GET /api/admin/certificates/*'], 'GET', '/api/admin/certificates/c1/logs')],
    ['certificate upload permission does not allow self signed create', false, canUseAPI('custom', ['POST /api/admin/certificates/upload'], 'POST', '/api/admin/certificates/self-signed')],
    ['certificate wildcard write allows mTLS update', true, canUseAPI('custom', ['POST /api/admin/certificates/*'], 'POST', '/api/admin/certificates/c1/mtls')],
    ['agent gateway read does not issue token', false, canUseAPI('custom', ['GET /api/admin/agent-gateways'], 'POST', '/api/admin/agent-gateways/g1/token')],
    ['agent gateway read allows runtime status', true, canUseAPI('custom', ['GET /api/admin/agent-gateways'], 'GET', '/api/admin/agent-gateways/status')],
    ['agent gateway token permission allows token issue', true, canUseAPI('custom', ['POST /api/admin/agent-gateways/*'], 'POST', '/api/admin/agent-gateways/g1/token')],
    ['gateway group read allows runtime status', true, canUseAPI('custom', ['GET /api/admin/gateway-groups'], 'GET', '/api/admin/gateway-groups/status')],
    ['scheduled task read does not allow run', false, canUseAPI('custom', ['GET /api/admin/scheduled-tasks'], 'POST', '/api/admin/scheduled-tasks/t1/run')],
    ['scheduled task wildcard read allows logs', true, canUseAPI('custom', ['GET /api/admin/scheduled-tasks/*'], 'GET', '/api/admin/scheduled-tasks/t1/logs')],
    ['scheduled task wildcard write allows run', true, canUseAPI('custom', ['POST /api/admin/scheduled-tasks/*'], 'POST', '/api/admin/scheduled-tasks/t1/run')],
    ['SQL work order wildcard write allows approve', true, canUseAPI('custom', ['POST /api/admin/sql-work-orders/*'], 'POST', '/api/admin/sql-work-orders/w1/approve')],
    ['command approval wildcard write allows execute', true, canUseAPI('custom', ['POST /api/admin/command-approvals/*'], 'POST', '/api/admin/command-approvals/a1/execute')],
  ]

  const failed = cases.filter(([, expected, actual]) => actual !== expected)
  if (failed.length) {
    for (const [name, expected, actual] of failed) {
      console.error(`RBAC permission check failed: ${name}; expected ${expected}, got ${actual}`)
    }
    process.exit(1)
  }
} finally {
  await fs.rm(tempPath, { force: true })
}
