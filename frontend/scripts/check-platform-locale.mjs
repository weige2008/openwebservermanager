import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const platformSource = readFileSync(join(root, 'src/lib/platform.ts'), 'utf8')
const platformPageSource = readFileSync(join(root, 'src/features/console/platform-page.tsx'), 'utf8')
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
