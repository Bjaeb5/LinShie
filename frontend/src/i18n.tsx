import { createContext, useContext, useState, ReactNode } from 'react'

export type Lang = 'ru' | 'en'

const T = {
  ru: {
    appName: 'LinShi',
    appDesc: 'Платформа аудита безопасности Linux-серверов',
    appDescShort: 'LinShi — интеллектуальная система мониторинга и аудита безопасности Linux-серверов. Анализирует конфигурацию, обнаруживает уязвимости и даёт конкретные рекомендации по защите в соответствии со стандартами CIS, NIST и OWASP.',
    nav: {
      dashboard: 'Дашборд',
      scans: 'Сканирования',
      hosts: 'Хосты',
      policies: 'Политики',
      users: 'Пользователи',
      tools: 'Инструменты защиты',
      cyberattacks: 'Анализ киберугроз',
      about: 'О создателе',
    },
    login: {
      title: 'Вход в систему',
      username: 'Логин',
      password: 'Пароль',
      submit: 'Войти',
      loading: 'Входим...',
      error: 'Неверный логин или пароль',
    },
    dashboard: {
      title: 'Дашборд безопасности',
      subtitle: 'Обзор состояния защиты серверов',
      startScan: 'Запустить сканирование',
      scanning: 'Сканирование...',
      securityIndex: 'Индекс безопасности',
      totalScans: 'сканирований',
      checkResults: 'Результаты проверок',
      vulnerabilities: 'Уязвимости',
      critical: 'Критические',
      high: 'Высокие',
      medium: 'Средние',
      low: 'Низкие',
      recentScans: 'Последние сканирования',
      noScans: 'Нет сканирований. Нажмите "Запустить сканирование".',
      localHost: 'Локальный хост',
      host: 'Хост',
      errors: 'ошибок',
      passed: 'Пройдено',
      failed: 'Ошибки',
      warnings: 'Предупреждения',
      scoreGood: 'Хорошо',
      scoreMedium: 'Среднее',
      scoreCritical: 'Критично',
      systemInfo: 'Информация о системе',
      compliance: 'Соответствие стандартам',
      quickActions: 'Быстрые действия',
    },
    common: {
      save: 'Сохранить',
      cancel: 'Отмена',
      delete: 'Удалить',
      add: 'Добавить',
      create: 'Создать',
      apply: 'Применить',
      close: 'Закрыть',
      logout: 'Выйти',
      loading: 'Загрузка...',
      noData: 'Нет данных',
      search: 'Поиск',
    },
  },
  en: {
    appName: 'LinShi',
    appDesc: 'Linux Server Security Audit Platform',
    appDescShort: 'LinShi is an intelligent monitoring and security audit system for Linux servers. It analyzes configuration, detects vulnerabilities and provides specific recommendations in accordance with CIS, NIST and OWASP standards.',
    nav: {
      dashboard: 'Dashboard',
      scans: 'Scans',
      hosts: 'Hosts',
      policies: 'Policies',
      users: 'Users',
      tools: 'Security Tools',
      cyberattacks: 'Cyber Threat Analysis',
      about: 'About Creator',
    },
    login: {
      title: 'Sign In',
      username: 'Username',
      password: 'Password',
      submit: 'Sign In',
      loading: 'Signing in...',
      error: 'Invalid username or password',
    },
    dashboard: {
      title: 'Security Dashboard',
      subtitle: 'Server protection overview',
      startScan: 'Start Scan',
      scanning: 'Scanning...',
      securityIndex: 'Security Index',
      totalScans: 'scans',
      checkResults: 'Check Results',
      vulnerabilities: 'Vulnerabilities',
      critical: 'Critical',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      recentScans: 'Recent Scans',
      noScans: 'No scans yet. Click "Start Scan".',
      localHost: 'Local Host',
      host: 'Host',
      errors: 'errors',
      passed: 'Passed',
      failed: 'Failed',
      warnings: 'Warnings',
      scoreGood: 'Good',
      scoreMedium: 'Medium',
      scoreCritical: 'Critical',
      systemInfo: 'System Information',
      compliance: 'Standards Compliance',
      quickActions: 'Quick Actions',
    },
    common: {
      save: 'Save',
      cancel: 'Cancel',
      delete: 'Delete',
      add: 'Add',
      create: 'Create',
      apply: 'Apply',
      close: 'Close',
      logout: 'Logout',
      loading: 'Loading...',
      noData: 'No data',
      search: 'Search',
    },
  }
}

export type Translations = typeof T.ru
const LangContext = createContext<{ lang: Lang; t: Translations; setLang: (l: Lang) => void }>({
  lang: 'ru', t: T.ru, setLang: () => {}
})

export function LangProvider({ children }: { children: ReactNode }) {
  const saved = (localStorage.getItem('lang') as Lang) || 'ru'
  const [lang, setLangState] = useState<Lang>(saved)
  const setLang = (l: Lang) => { setLangState(l); localStorage.setItem('lang', l) }
  return <LangContext.Provider value={{ lang, t: T[lang], setLang }}>{children}</LangContext.Provider>
}

export const useLang = () => useContext(LangContext)
