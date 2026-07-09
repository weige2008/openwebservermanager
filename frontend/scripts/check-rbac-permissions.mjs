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
