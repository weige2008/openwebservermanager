import i18n from 'i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import { initReactI18next } from 'react-i18next'

import { normalizeInterfaceLanguage } from './languages'
import { resources } from './resources'

const legacyLocale = localStorage.getItem('servermanager:locale')
if (legacyLocale && !localStorage.getItem('i18nextLng')) {
  localStorage.setItem('i18nextLng', normalizeInterfaceLanguage(legacyLocale))
  localStorage.removeItem('servermanager:locale')
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: 'en',
    supportedLngs: ['en', 'zh', 'zh-TW', 'fr', 'ru', 'ja', 'vi'],
    load: 'currentOnly',
    nsSeparator: false,
    debug: false,
    interpolation: {
      escapeValue: false,
    },
    detection: {
      order: ['localStorage', 'navigator'],
      caches: ['localStorage'],
    },
  })

export default i18n
