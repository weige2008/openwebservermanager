export const INTERFACE_LANGUAGE_OPTIONS = [
  { code: 'zh', label: '简体中文' },
  { code: 'en', label: 'English' },
  { code: 'zh-TW', label: '繁體中文' },
  { code: 'fr', label: 'Français' },
  { code: 'ru', label: 'Русский' },
  { code: 'ja', label: '日本語' },
  { code: 'vi', label: 'Tiếng Việt' },
] as const

export type InterfaceLanguageCode = (typeof INTERFACE_LANGUAGE_OPTIONS)[number]['code']

export function normalizeInterfaceLanguage(value?: string | null): InterfaceLanguageCode {
  if (!value) return 'en'

  const normalized = value.trim().replace(/_/g, '-').toLowerCase()
  if (normalized === 'zh-tw' || normalized === 'zh-hk' || normalized === 'zh-mo') return 'zh-TW'
  if (normalized.startsWith('zh')) return 'zh'

  const match = INTERFACE_LANGUAGE_OPTIONS.find((lang) => lang.code.toLowerCase() === normalized)
  return match?.code ?? 'en'
}
