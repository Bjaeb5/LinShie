import { useState } from 'react'
import { Wrench, ChevronDown, ChevronUp, Shield, Terminal, Search } from 'lucide-react'
import { useLang } from '../i18n'

const TOOLS = [
  {
    name: 'Fail2Ban',
    category: 'Защита от брутфорса',
    icon: '🛡️',
    color: 'from-red-900/40 to-red-800/20 border-red-800/50',
    description: {
      ru: 'Автоматически блокирует IP-адреса после нескольких неудачных попыток входа. Мониторит лог-файлы и создаёт правила iptables/nftables.',
      en: 'Automatically blocks IP addresses after multiple failed login attempts. Monitors log files and creates iptables/nftables rules.',
    },
    attacks: {
      ru: ['SSH Brute Force', 'FTP брутфорс', 'HTTP Basic Auth атаки', 'SMTP перебор паролей'],
      en: ['SSH Brute Force', 'FTP Brute Force', 'HTTP Basic Auth attacks', 'SMTP password spraying'],
    },
    install: `# Установка
sudo apt-get install -y fail2ban

# Создание локальной конфигурации
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Настройка (sudo nano /etc/fail2ban/jail.local)
[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
maxretry = 3
bantime  = 3600
findtime = 600

# Запуск
sudo systemctl enable --now fail2ban

# Проверка статуса
sudo fail2ban-client status sshd`,
  },
  {
    name: 'UFW (Uncomplicated Firewall)',
    category: 'Фаервол',
    icon: '🔥',
    color: 'from-orange-900/40 to-orange-800/20 border-orange-800/50',
    description: {
      ru: 'Простой интерфейс для управления iptables. Позволяет гибко настраивать правила входящего и исходящего трафика.',
      en: 'Simple interface for managing iptables. Allows flexible configuration of inbound and outbound traffic rules.',
    },
    attacks: {
      ru: ['Сканирование портов (Nmap)', 'DDoS атаки', 'Несанкционированный доступ к сервисам', 'Lateral Movement'],
      en: ['Port scanning (Nmap)', 'DDoS attacks', 'Unauthorized service access', 'Lateral Movement'],
    },
    install: `# Установка
sudo apt-get install -y ufw

# Базовые правила
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Разрешить SSH (обязательно перед включением!)
sudo ufw allow 22/tcp

# Разрешить веб
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Включить фаервол
sudo ufw --force enable

# Проверка
sudo ufw status verbose`,
  },
  {
    name: 'auditd',
    category: 'Аудит и мониторинг',
    icon: '📋',
    color: 'from-yellow-900/40 to-yellow-800/20 border-yellow-800/50',
    description: {
      ru: 'Подсистема аудита ядра Linux. Записывает системные вызовы, изменения файлов, действия пользователей для расследования инцидентов.',
      en: 'Linux kernel audit subsystem. Records system calls, file changes, user actions for incident investigation.',
    },
    attacks: {
      ru: ['Privilege Escalation', 'Модификация конфигурационных файлов', 'Несанкционированное выполнение команд', 'Утечка данных'],
      en: ['Privilege Escalation', 'Configuration file modification', 'Unauthorized command execution', 'Data exfiltration'],
    },
    install: `# Установка
sudo apt-get install -y auditd audispd-plugins

# Включение
sudo systemctl enable --now auditd

# Добавление правил аудита
sudo auditctl -w /etc/passwd -p wa -k identity
sudo auditctl -w /etc/shadow -p wa -k identity
sudo auditctl -w /etc/sudoers -p wa -k sudoers
sudo auditctl -a always,exit -F arch=b64 -S execve -k commands

# Сохранить правила постоянно
sudo nano /etc/audit/rules.d/audit.rules

# Просмотр логов
sudo ausearch -k identity
sudo aureport --auth`,
  },
  {
    name: 'AppArmor',
    category: 'Мандатный контроль доступа',
    icon: '🔒',
    color: 'from-purple-900/40 to-purple-800/20 border-purple-800/50',
    description: {
      ru: 'Система мандатного контроля доступа (MAC). Ограничивает возможности программ через профили — даже при компрометации приложение не может выйти за пределы профиля.',
      en: 'Mandatory Access Control (MAC) system. Restricts program capabilities through profiles — even if compromised, the app cannot exceed profile limits.',
    },
    attacks: {
      ru: ['Container Escape', 'Privilege Escalation через приложения', 'Эксплуатация уязвимостей ПО', 'Lateral Movement'],
      en: ['Container Escape', 'Application privilege escalation', 'Software vulnerability exploitation', 'Lateral Movement'],
    },
    install: `# Установка
sudo apt-get install -y apparmor apparmor-utils apparmor-profiles

# Включение
sudo systemctl enable --now apparmor

# Перевод всех профилей в режим enforce
sudo aa-enforce /etc/apparmor.d/*

# Проверка статуса профилей
sudo aa-status

# Просмотр нарушений
sudo aa-logprof

# Создание профиля для приложения
sudo aa-genprof /usr/bin/myapp`,
  },
  {
    name: 'ClamAV',
    category: 'Антивирус',
    icon: '🦠',
    color: 'from-green-900/40 to-green-800/20 border-green-800/50',
    description: {
      ru: 'Антивирусный движок с открытым исходным кодом. Сканирует файлы, почту, веб-трафик на наличие вирусов, троянов и вредоносного ПО.',
      en: 'Open source antivirus engine. Scans files, email, web traffic for viruses, trojans and malware.',
    },
    attacks: {
      ru: ['Вирусы и трояны', 'Веб-шеллы', 'Вредоносные файлы в загрузках', 'Email-фишинг с вложениями'],
      en: ['Viruses and trojans', 'Web shells', 'Malicious files in uploads', 'Email phishing with attachments'],
    },
    install: `# Установка
sudo apt-get install -y clamav clamav-daemon

# Остановить для обновления БД
sudo systemctl stop clamav-freshclam

# Обновить базу сигнатур
sudo freshclam

# Запустить
sudo systemctl enable --now clamav-daemon
sudo systemctl enable --now clamav-freshclam

# Сканирование директории
sudo clamscan -r /var/www --infected --remove

# Настройка автосканирования (cron)
echo "0 2 * * * root clamscan -r /home --quiet --infected" | sudo tee /etc/cron.d/clamav`,
  },
  {
    name: 'OSSEC / Wazuh',
    category: 'IDS/HIDS',
    icon: '👁️',
    color: 'from-cyan-900/40 to-cyan-800/20 border-cyan-800/50',
    description: {
      ru: 'Host-based система обнаружения вторжений (HIDS). Анализирует логи, проверяет целостность файлов, мониторит rootkit-активность в реальном времени.',
      en: 'Host-based Intrusion Detection System (HIDS). Analyzes logs, checks file integrity, monitors rootkit activity in real time.',
    },
    attacks: {
      ru: ['Rootkit установка', 'Изменение системных файлов', 'Подозрительная активность пользователей', 'Log tampering'],
      en: ['Rootkit installation', 'System file modification', 'Suspicious user activity', 'Log tampering'],
    },
    install: `# Установка Wazuh Agent (рекомендуется)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo apt-get install -y wazuh-agent

# Настройка (укажите IP сервера Wazuh)
sudo WAZUH_MANAGER='YOUR_WAZUH_SERVER_IP' apt-get install wazuh-agent

# Запуск
sudo systemctl enable --now wazuh-agent

# Проверка статуса
sudo systemctl status wazuh-agent`,
  },
  {
    name: 'rkhunter',
    category: 'Антируткит',
    icon: '🔍',
    color: 'from-pink-900/40 to-pink-800/20 border-pink-800/50',
    description: {
      ru: 'Сканер руткитов, бэкдоров и локальных эксплойтов. Проверяет MD5-хэши системных файлов, права доступа, скрытые файлы и подозрительные строки.',
      en: 'Rootkit, backdoor and local exploit scanner. Checks MD5 hashes of system files, permissions, hidden files and suspicious strings.',
    },
    attacks: {
      ru: ['Rootkit установка', 'Backdoor-программы', 'Подмена системных бинарников', 'Скрытые процессы'],
      en: ['Rootkit installation', 'Backdoor programs', 'System binary replacement', 'Hidden processes'],
    },
    install: `# Установка
sudo apt-get install -y rkhunter

# Обновление базы данных
sudo rkhunter --update
sudo rkhunter --propupd

# Запуск проверки
sudo rkhunter --check --sk

# Проверка только файлов
sudo rkhunter --check --rwo

# Автоматическая проверка (cron)
echo "0 3 * * * root rkhunter --check --cronjob --report-warnings-only" | sudo tee /etc/cron.d/rkhunter

# Просмотр лога
sudo cat /var/log/rkhunter.log`,
  },
  {
    name: 'Lynis',
    category: 'Аудит безопасности',
    icon: '📊',
    color: 'from-blue-900/40 to-blue-800/20 border-blue-800/50',
    description: {
      ru: 'Инструмент аудита безопасности и соответствия требованиям для Linux/Unix. Проводит глубокий анализ системы и выдаёт рекомендации по улучшению.',
      en: 'Security auditing and compliance tool for Linux/Unix. Performs deep system analysis and provides improvement recommendations.',
    },
    attacks: {
      ru: ['Неправильная конфигурация', 'Устаревшее ПО', 'Слабые политики безопасности', 'Несоответствие стандартам CIS/NIST'],
      en: ['Misconfiguration', 'Outdated software', 'Weak security policies', 'Non-compliance with CIS/NIST'],
    },
    install: `# Установка
sudo apt-get install -y lynis

# Полный аудит системы
sudo lynis audit system

# Только проверка конфигурации
sudo lynis audit system --quick

# Проверка соответствия CIS
sudo lynis audit system --profile /etc/lynis/default.prf

# Автоматический запуск (cron)
echo "0 4 * * 0 root lynis audit system --cronjob" | sudo tee /etc/cron.d/lynis

# Отчёт
sudo cat /var/log/lynis.log
sudo cat /var/log/lynis-report.dat`,
  },
]

export default function Tools() {
  const { lang } = useLang()
  const [expanded, setExpanded] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [activeCategory, setActiveCategory] = useState('all')

  const categories = ['all', ...Array.from(new Set(TOOLS.map(t => t.category)))]
  const filtered = TOOLS.filter(t => {
    const matchSearch = t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.description[lang].toLowerCase().includes(search.toLowerCase())
    const matchCat = activeCategory === 'all' || t.category === activeCategory
    return matchSearch && matchCat
  })

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Wrench className="w-6 h-6 text-blue-400" />
          {lang === 'ru' ? 'Инструменты защиты Linux' : 'Linux Security Tools'}
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          {lang === 'ru'
            ? 'Каталог программ безопасности с описанием, защищаемыми атаками и инструкцией по установке'
            : 'Security software catalog with descriptions, protected attacks and installation guide'}
        </p>
      </div>

      {/* Search + filter */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder={lang === 'ru' ? 'Поиск инструментов...' : 'Search tools...'}
            className="w-full bg-gray-900 border border-gray-800 text-white pl-9 pr-4 py-2 rounded-lg text-sm focus:outline-none focus:border-blue-500" />
        </div>
        <div className="flex flex-wrap gap-2">
          {categories.map(c => (
            <button key={c} onClick={() => setActiveCategory(c)}
              className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
                activeCategory === c ? 'bg-blue-600 border-blue-500 text-white' : 'bg-gray-900 border-gray-700 text-gray-400 hover:text-white'
              }`}>
              {c === 'all' ? (lang === 'ru' ? 'Все' : 'All') : c}
            </button>
          ))}
        </div>
      </div>

      {/* Tools grid */}
      <div className="space-y-3">
        {filtered.map(tool => (
          <div key={tool.name} className={`bg-gradient-to-r ${tool.color} border rounded-xl overflow-hidden`}>
            <button className="w-full p-5 text-left"
              onClick={() => setExpanded(expanded === tool.name ? null : tool.name)}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <span className="text-3xl">{tool.icon}</span>
                  <div>
                    <div className="font-bold text-white text-lg">{tool.name}</div>
                    <div className="text-xs text-gray-400 mt-0.5">{tool.category}</div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="hidden sm:flex flex-wrap gap-1.5">
                    {tool.attacks[lang].slice(0, 2).map(a => (
                      <span key={a} className="text-xs bg-black/30 text-gray-300 px-2 py-0.5 rounded border border-gray-700">{a}</span>
                    ))}
                  </div>
                  {expanded === tool.name ? <ChevronUp className="w-5 h-5 text-gray-400 flex-shrink-0" /> : <ChevronDown className="w-5 h-5 text-gray-400 flex-shrink-0" />}
                </div>
              </div>
            </button>

            {expanded === tool.name && (
              <div className="px-5 pb-5 space-y-4 border-t border-white/10 pt-4">
                {/* Description */}
                <p className="text-sm text-gray-300">{tool.description[lang]}</p>

                {/* Attacks prevented */}
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Shield className="w-4 h-4 text-green-400" />
                    <span className="text-sm font-medium text-green-400">
                      {lang === 'ru' ? 'Предотвращаемые атаки:' : 'Prevented attacks:'}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {tool.attacks[lang].map(a => (
                      <span key={a} className="text-xs bg-green-900/30 text-green-300 border border-green-800/50 px-2.5 py-1 rounded-lg">
                        ✓ {a}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Install guide */}
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Terminal className="w-4 h-4 text-blue-400" />
                    <span className="text-sm font-medium text-blue-400">
                      {lang === 'ru' ? 'Инструкция по установке:' : 'Installation guide:'}
                    </span>
                  </div>
                  <pre className="bg-gray-950 border border-gray-800 rounded-lg p-4 text-xs text-green-300 overflow-x-auto whitespace-pre font-mono leading-relaxed">
                    {tool.install}
                  </pre>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
