import i18n from '@/i18n/config'
import { INTERFACE_LANGUAGE_OPTIONS, normalizeInterfaceLanguage } from '@/i18n/languages'
import type { InterfaceLanguageCode } from '@/i18n/languages'

const shortLabels: Record<InterfaceLanguageCode, string> = {
  zh: '中',
  en: 'EN',
  'zh-TW': '繁',
  fr: 'FR',
  ru: 'RU',
  ja: '日',
  vi: 'VI',
}

export const languageOptions = INTERFACE_LANGUAGE_OPTIONS.map((option) => ({
  code: option.code,
  label: option.label,
  shortLabel: shortLabels[option.code],
}))

export type Locale = InterfaceLanguageCode

export function translate(locale: string, key: string, fallback = key) {
  return i18n.t(key, { lng: normalizeInterfaceLanguage(locale), defaultValue: fallback })
}
