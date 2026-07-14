import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const platformSource = readFileSync(join(root, 'src/lib/platform.ts'), 'utf8')
const platformPageSource = readFileSync(join(root, 'src/features/console/platform-page.tsx'), 'utf8')
const workspaceSource = readFileSync(join(root, 'src/features/workspace/workspace-view.tsx'), 'utf8')
const resourcesSource = readFileSync(join(root, 'src/i18n/resources.ts'), 'utf8')

const mojibakeFragments = [
  '�',
  '€',
  '銆',
  '璧勪',
  '缁熶',
  '鐢ㄦ',
  '鏃ュ',
  '绯荤',
  '鎺ュ',
  '鍛戒',
  '鏁版',
  '閮ㄩ',
  '瑙掕',
  '鐧诲',
  '瀹氭',
  '鎿嶄',
  '绂荤',
  '韬',
  '乁',
  '丄',
  '丏',
  '乵',
]

const found = mojibakeFragments.filter((fragment) => platformSource.includes(fragment))

if (found.length > 0) {
  console.error(`platform locale text contains mojibake fragments: ${found.join(', ')}`)
  process.exit(1)
}

const accessPortalHardcodedText = [
  '>接入门户<',
  '>管理资产<',
  "title='文本协议'",
  "title='图形协议'",
  "title='Web资产'",
  "title='数据库资产'",
  '>接入<',
  '>暂无授权资源。<',
]
const hardcodedFound = accessPortalHardcodedText.filter((fragment) => platformPageSource.includes(fragment))
if (hardcodedFound.length > 0) {
  console.error(`access portal contains hardcoded locale text: ${hardcodedFound.join(', ')}`)
  process.exit(1)
}

const accessPageDefinitions = resourcesSource.match(/accessPage:\s*\{/g) || []
if (accessPageDefinitions.length !== 7) {
  console.error(`accessPage locale definitions = ${accessPageDefinitions.length}, want 7`)
  process.exit(1)
}

const sqlDialogDefinitions = resourcesSource.match(/sqlDialog:\s*\{/g) || []
if (sqlDialogDefinitions.length !== 7) {
  console.error(`sqlDialog locale definitions = ${sqlDialogDefinitions.length}, want 7`)
  process.exit(1)
}

const sshExecDefinitions = resourcesSource.match(/sshExecDialog:\s*\{/g) || []
if (sshExecDefinitions.length !== 7) {
  console.error(`sshExecDialog locale definitions = ${sshExecDefinitions.length}, want 7`)
  process.exit(1)
}

const sshFileManagerDefinitions = resourcesSource.match(/sshFileManager:\s*\{/g) || []
if (sshFileManagerDefinitions.length !== 7) {
  console.error(`sshFileManager locale definitions = ${sshFileManagerDefinitions.length}, want 7`)
  process.exit(1)
}

const toolsPageDefinitions = resourcesSource.match(/toolsPage:\s*\{/g) || []
if (toolsPageDefinitions.length !== 2) {
  console.error(`toolsPage locale definitions = ${toolsPageDefinitions.length}, want 2 (English and Simplified Chinese; other locales inherit fallback text)`)
  process.exit(1)
}

const toolsPageStart = platformPageSource.indexOf('function ToolsPage(')
const toolsPageEnd = platformPageSource.indexOf('function MonitoringPage(', toolsPageStart)
const toolsPageSource = toolsPageStart >= 0 && toolsPageEnd > toolsPageStart ? platformPageSource.slice(toolsPageStart, toolsPageEnd) : ''
const toolsPageHardcodedText = ['>实用工具<', '检测目标地址连通性', '检测中', '开始检测', '暂无检测结果', '当前账号没有执行诊断工具']
const toolsPageHardcodedFound = toolsPageHardcodedText.filter((fragment) => toolsPageSource.includes(fragment))
if (toolsPageHardcodedFound.length > 0) {
  console.error(`tools page contains hardcoded locale text: ${toolsPageHardcodedFound.join(', ')}`)
  process.exit(1)
}

const monitoringPageDefinitions = resourcesSource.match(/monitoringPage:\s*\{/g) || []
if (monitoringPageDefinitions.length !== 2) {
  console.error(`monitoringPage locale definitions = ${monitoringPageDefinitions.length}, want 2 (English and Simplified Chinese; other locales inherit fallback text)`)
  process.exit(1)
}

const monitoringPageStart = platformPageSource.indexOf('function MonitoringPage(')
const monitoringPageEnd = platformPageSource.indexOf('function BackupsPage(', monitoringPageStart)
const monitoringPageSource = monitoringPageStart >= 0 && monitoringPageEnd > monitoringPageStart ? platformPageSource.slice(monitoringPageStart, monitoringPageEnd) : ''
const monitoringPageHardcodedText = ['>系统监控<', '集中查看服务', '>刷新<', '当前账号没有读取系统监控', "['Status'", "['Users'", "['Uptime'"]
const monitoringPageHardcodedFound = monitoringPageHardcodedText.filter((fragment) => monitoringPageSource.includes(fragment))
if (monitoringPageHardcodedFound.length > 0) {
  console.error(`monitoring page contains hardcoded locale text: ${monitoringPageHardcodedFound.join(', ')}`)
  process.exit(1)
}

const backupsPageDefinitions = resourcesSource.match(/backupsPage:\s*\{/g) || []
if (backupsPageDefinitions.length !== 2) {
  console.error(`backupsPage locale definitions = ${backupsPageDefinitions.length}, want 2 (English and Simplified Chinese; other locales inherit fallback text)`)
  process.exit(1)
}

const backupsPageStart = platformPageSource.indexOf('function BackupsPage(')
const backupsPageEnd = platformPageSource.indexOf('async function submitBackupFile(', backupsPageStart)
const backupsPageSource = backupsPageStart >= 0 && backupsPageEnd > backupsPageStart ? platformPageSource.slice(backupsPageStart, backupsPageEnd) : ''
const backupsPageHardcodedText = ['备份已创建', '备份校验通过', '恢复备份并覆盖当前数据', '>上传恢复<', '>立即备份<', '>校验<', '>恢复<', '>下载<', '>删除<', '暂无备份', '当前账号没有查看备份']
const backupsPageHardcodedFound = backupsPageHardcodedText.filter((fragment) => backupsPageSource.includes(fragment))
if (backupsPageHardcodedFound.length > 0) {
  console.error(`backups page contains hardcoded locale text: ${backupsPageHardcodedFound.join(', ')}`)
  process.exit(1)
}

for (const fragment of ['backupUploadKey(uploadFile)', 'nextFile.size > 512 * 1024 * 1024', '!uploadFile || !uploadValidated', 'disabled={!uploadValidated || restoring}']) {
  if (!backupsPageSource.includes(fragment)) {
    console.error(`backups page is missing validated restore guard: ${fragment}`)
    process.exit(1)
  }
}

for (const endpoint of ['/sftp/mkdir', '/sftp/write', '/sftp/${fileActionMode}']) {
  if (!workspaceSource.includes(endpoint)) {
    console.error(`SSH file manager is missing endpoint: ${endpoint}`)
    process.exit(1)
  }
}

const sshExecStart = platformPageSource.indexOf('function SSHExecDialog(')
const sshExecEnd = platformPageSource.indexOf('function SQLWorkOrderDecisionDialog(', sshExecStart)
const sshExecSource = sshExecStart >= 0 && sshExecEnd > sshExecStart ? platformPageSource.slice(sshExecStart, sshExecEnd) : ''
const sshExecHardcodedText = ['SSH command executed', "label='Command'", "label='Timeout seconds'", '>Close</Button>', "'Running...' : 'Run'", '(stdout empty)', '(stderr empty)']
const sshExecHardcodedFound = sshExecHardcodedText.filter((fragment) => sshExecSource.includes(fragment))
if (sshExecHardcodedFound.length > 0) {
  console.error(`SSH Exec dialog contains hardcoded locale text: ${sshExecHardcodedFound.join(', ')}`)
  process.exit(1)
}

const sqlDialogHardcodedText = [
  "label='申请原因'",
  '>关闭</Button>',
  "'提交中' : '提交工单'",
  "'执行中' : '执行'",
  "'SQL 工单已执行'",
  "'SQL 工单已提交'",
]
const sqlDialogStart = platformPageSource.indexOf('function SQLExecuteDialog(')
const sqlDialogEnd = platformPageSource.indexOf('function SQLResultPanel(', sqlDialogStart)
const sqlDialogSource = sqlDialogStart >= 0 && sqlDialogEnd > sqlDialogStart ? platformPageSource.slice(sqlDialogStart, sqlDialogEnd) : ''
const sqlHardcodedFound = sqlDialogHardcodedText.filter((fragment) => sqlDialogSource.includes(fragment))
if (sqlHardcodedFound.length > 0) {
  console.error(`SQL dialog contains hardcoded locale text: ${sqlHardcodedFound.join(', ')}`)
  process.exit(1)
}

const popupOpenIndex = platformPageSource.indexOf('const popup = openAccessPopup()')
const popupMFAIndex = platformPageSource.indexOf('await ensureAccessMFA(`/api/access/http/${item.id}/mfa`')
const popupNavigateIndex = platformPageSource.indexOf('popup.location.replace(`/api/access/http/${item.id}/proxy/`)')
if (popupOpenIndex < 0 || popupMFAIndex < 0 || popupNavigateIndex < 0 || !(popupOpenIndex < popupMFAIndex && popupMFAIndex < popupNavigateIndex)) {
  console.error('web asset access must synchronously open a popup before MFA and navigate it only after verification')
  process.exit(1)
}
