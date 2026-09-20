import { createI18n } from 'vue-i18n'
import fa from '../locales/fa.json'
import ru from '../locales/ru.json'
import en from '../locales/en.json'
import zh from '../locales/zh.json'

const messages = { fa, ru, en, zh }

function applyDirection(locale: string) {
  const rtl = locale === 'fa'
  document.documentElement.lang = locale
  document.documentElement.dir = rtl ? 'rtl' : 'ltr'
}

function getInitialLocale(): 'fa' | 'ru' | 'en' | 'zh' {
  const stored = localStorage.getItem('primevpn-locale')
  if (stored && ['fa', 'ru', 'en', 'zh'].includes(stored)) return stored as 'fa' | 'ru' | 'en' | 'zh'
  return 'fa'
}

const initialLocale = getInitialLocale()
applyDirection(initialLocale)

export const i18n = createI18n({
  legacy: false,
  locale: initialLocale,
  fallbackLocale: 'fa',
  messages,
})

export function setLocale(locale: string) {
  if (['fa', 'ru', 'en', 'zh'].includes(locale)) {
    localStorage.setItem('primevpn-locale', locale)
    i18n.global.locale.value = locale as 'fa' | 'ru' | 'en' | 'zh'
    applyDirection(locale)
  }
}
