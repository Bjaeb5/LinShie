import { useState } from 'react'
import { Zap, ChevronDown, ChevronUp, AlertTriangle, CheckCircle, XCircle, Shield } from 'lucide-react'
import { useLang } from '../i18n'

const ATTACKS = [
  {
    id: 'brute_force',
    name: { ru: 'Брутфорс SSH/RDP', en: 'SSH/RDP Brute Force' },
    severity: 'critical',
    icon: '🔓',
    description: {
      ru: 'Автоматический перебор паролей для получения доступа к SSH или RDP сервисам. Один из наиболее распространённых векторов атак на серверы.',
      en: 'Automated password guessing to gain access to SSH or RDP services. One of the most common attack vectors against servers.',
    },
    indicators: {
      ru: ['Множество неудачных попыток входа в /var/log/auth.log', 'Высокая нагрузка на CPU от sshd', 'Подозрительные IP в логах'],
      en: ['Multiple failed login attempts in /var/log/auth.log', 'High CPU load from sshd', 'Suspicious IPs in logs'],
    },
    checks: ['ssh_root_login', 'ssh_password_auth', 'ssh_max_auth'],
    prevention: {
      ru: ['Установить Fail2Ban', 'Отключить парольную аутентификацию SSH', 'Использовать нестандартный порт', 'Включить двухфакторную аутентификацию', 'Настроить AllowUsers в sshd_config'],
      en: ['Install Fail2Ban', 'Disable SSH password authentication', 'Use non-standard port', 'Enable two-factor authentication', 'Configure AllowUsers in sshd_config'],
    },
    tools: ['Fail2Ban', 'UFW'],
  },
  {
    id: 'ddos',
    name: { ru: 'DDoS / DoS атаки', en: 'DDoS / DoS Attacks' },
    severity: 'high',
    icon: '🌊',
    description: {
      ru: 'Атаки типа "отказ в обслуживании" направлены на исчерпание ресурсов сервера (CPU, RAM, bandwidth) путём отправки огромного количества запросов.',
      en: 'Denial of Service attacks aim to exhaust server resources (CPU, RAM, bandwidth) by sending a massive number of requests.',
    },
    indicators: {
      ru: ['Аномально высокий трафик', 'Деградация производительности', 'Тысячи соединений с одного IP', 'Высокая нагрузка на сеть'],
      en: ['Abnormally high traffic', 'Performance degradation', 'Thousands of connections from one IP', 'High network load'],
    },
    checks: ['net_firewall', 'net_syncookies'],
    prevention: {
      ru: ['Включить TCP SYN Cookies (sysctl)', 'Настроить iptables rate limiting', 'Использовать CDN/Anti-DDoS провайдера', 'Ограничить количество соединений в UFW', 'Настроить fail2ban для HTTP'],
      en: ['Enable TCP SYN Cookies (sysctl)', 'Configure iptables rate limiting', 'Use CDN/Anti-DDoS provider', 'Limit connections in UFW', 'Configure fail2ban for HTTP'],
    },
    tools: ['UFW', 'Fail2Ban'],
  },
  {
    id: 'privilege_escalation',
    name: { ru: 'Повышение привилегий', en: 'Privilege Escalation' },
    severity: 'critical',
    icon: '⬆️',
    description: {
      ru: 'Атакующий, получив минимальный доступ, использует уязвимости ядра, SUID-файлы или misconfiguration для получения root-привилегий.',
      en: 'An attacker with minimal access exploits kernel vulnerabilities, SUID files or misconfiguration to gain root privileges.',
    },
    indicators: {
      ru: ['Подозрительные SUID файлы', 'Необычные записи в /etc/sudoers', 'Изменения системных бинарников', 'Новые root-процессы'],
      en: ['Suspicious SUID files', 'Unusual entries in /etc/sudoers', 'System binary modifications', 'New root processes'],
    },
    checks: ['sys_suid', 'sys_apparmor', 'sys_updates'],
    prevention: {
      ru: ['Регулярно обновлять ядро и ПО', 'Настроить AppArmor/SELinux', 'Аудит SUID файлов (rkhunter)', 'Принцип минимальных привилегий в sudo', 'Мониторинг auditd'],
      en: ['Regularly update kernel and software', 'Configure AppArmor/SELinux', 'Audit SUID files (rkhunter)', 'Principle of least privilege in sudo', 'Monitor with auditd'],
    },
    tools: ['AppArmor', 'auditd', 'rkhunter'],
  },
  {
    id: 'ransomware',
    name: { ru: 'Ransomware / Шифровальщики', en: 'Ransomware' },
    severity: 'critical',
    icon: '💀',
    description: {
      ru: 'Вредоносное ПО шифрует файлы сервера и требует выкуп. Распространяется через уязвимости, фишинг или скомпрометированные учётные данные.',
      en: 'Malware encrypts server files and demands ransom. Spreads through vulnerabilities, phishing or compromised credentials.',
    },
    indicators: {
      ru: ['Внезапно зашифрованные файлы', 'Высокая активность диска', 'Файлы README с требованием выкупа', 'Аномальные процессы шифрования'],
      en: ['Suddenly encrypted files', 'High disk activity', 'README files with ransom demands', 'Anomalous encryption processes'],
    },
    checks: ['sys_updates', 'sys_auditd', 'sys_apparmor'],
    prevention: {
      ru: ['Регулярные бэкапы (правило 3-2-1)', 'Изоляция сервисов (AppArmor)', 'Мониторинг файловой активности', 'Принцип минимального доступа', 'Сегментация сети'],
      en: ['Regular backups (3-2-1 rule)', 'Service isolation (AppArmor)', 'File activity monitoring', 'Principle of least access', 'Network segmentation'],
    },
    tools: ['AppArmor', 'ClamAV', 'auditd'],
  },
  {
    id: 'mitm',
    name: { ru: 'Man-in-the-Middle (MITM)', en: 'Man-in-the-Middle (MITM)' },
    severity: 'high',
    icon: '👥',
    description: {
      ru: 'Атакующий перехватывает трафик между сервером и клиентами. Возможно при использовании слабого шифрования или HTTP вместо HTTPS.',
      en: 'Attacker intercepts traffic between server and clients. Possible when using weak encryption or HTTP instead of HTTPS.',
    },
    indicators: {
      ru: ['Предупреждения об SSL-сертификатах', 'Неожиданные изменения ARP-таблиц', 'Перехваченные учётные данные', 'Аномальный сетевой трафик'],
      en: ['SSL certificate warnings', 'Unexpected ARP table changes', 'Intercepted credentials', 'Anomalous network traffic'],
    },
    checks: ['crypto_ciphers', 'crypto_macs', 'net_firewall'],
    prevention: {
      ru: ['Использовать только TLS 1.2/1.3', 'Настроить HSTS заголовки', 'Отключить слабые шифры SSH', 'Использовать сертификаты Let\'s Encrypt', 'Мониторинг сертификатов'],
      en: ['Use only TLS 1.2/1.3', 'Configure HSTS headers', 'Disable weak SSH ciphers', 'Use Let\'s Encrypt certificates', 'Monitor certificates'],
    },
    tools: ['UFW', 'Lynis'],
  },
  {
    id: 'web_shell',
    name: { ru: 'Веб-шеллы / RCE', en: 'Web Shells / RCE' },
    severity: 'critical',
    icon: '🕷️',
    description: {
      ru: 'Злоумышленник загружает вредоносный скрипт (веб-шелл) через уязвимости веб-приложения для получения удалённого выполнения кода на сервере.',
      en: 'Attacker uploads malicious script (web shell) through web application vulnerabilities to gain remote code execution on the server.',
    },
    indicators: {
      ru: ['Необычные PHP/Python/Perl файлы в веб-директории', 'Подозрительные запросы в access.log', 'Новые процессы от www-data', 'Изменения файлов в ночное время'],
      en: ['Unusual PHP/Python/Perl files in web directory', 'Suspicious requests in access.log', 'New processes from www-data', 'File changes at night'],
    },
    checks: ['sys_apparmor', 'sys_auditd', 'sys_updates'],
    prevention: {
      ru: ['Настроить AppArmor для веб-сервера', 'Запретить выполнение в upload-директориях', 'Сканировать загрузки ClamAV', 'Мониторинг целостности файлов (auditd)', 'WAF (ModSecurity)'],
      en: ['Configure AppArmor for web server', 'Deny execution in upload directories', 'Scan uploads with ClamAV', 'File integrity monitoring (auditd)', 'WAF (ModSecurity)'],
    },
    tools: ['AppArmor', 'ClamAV', 'auditd'],
  },
  {
    id: 'supply_chain',
    name: { ru: 'Supply Chain атаки', en: 'Supply Chain Attacks' },
    severity: 'high',
    icon: '📦',
    description: {
      ru: 'Компрометация программного обеспечения или зависимостей на этапе разработки или дистрибуции. Вредоносный код попадает через обновления легитимного ПО.',
      en: 'Compromise of software or dependencies during development or distribution. Malicious code arrives through legitimate software updates.',
    },
    indicators: {
      ru: ['Неожиданные сетевые соединения после обновлений', 'Изменения в хэшах пакетов', 'Аномальное поведение после apt upgrade', 'Неавторизованные репозитории'],
      en: ['Unexpected network connections after updates', 'Changes in package hashes', 'Anomalous behavior after apt upgrade', 'Unauthorized repositories'],
    },
    checks: ['sys_updates', 'sys_auditd'],
    prevention: {
      ru: ['Использовать только официальные репозитории', 'Проверять GPG подписи пакетов', 'Тестировать обновления в staging', 'Мониторинг изменений после обновлений', 'Использовать SBOM'],
      en: ['Use only official repositories', 'Verify package GPG signatures', 'Test updates in staging', 'Monitor changes after updates', 'Use SBOM'],
    },
    tools: ['auditd', 'rkhunter', 'Lynis'],
  },
  {
    id: 'lateral_movement',
    name: { ru: 'Lateral Movement', en: 'Lateral Movement' },
    severity: 'high',
    icon: '🔄',
    description: {
      ru: 'После компрометации одного хоста атакующий перемещается по сети, используя украденные учётные данные или доверенные соединения между серверами.',
      en: 'After compromising one host, the attacker moves through the network using stolen credentials or trusted connections between servers.',
    },
    indicators: {
      ru: ['Необычные SSH-соединения между серверами', 'Использование служебных аккаунтов в нестандартное время', 'Копирование файлов между хостами', 'Новые SSH authorized_keys'],
      en: ['Unusual SSH connections between servers', 'Service account usage at unusual times', 'File copying between hosts', 'New SSH authorized_keys'],
    },
    checks: ['ssh_root_login', 'net_firewall', 'sys_auditd'],
    prevention: {
      ru: ['Сегментация сети (VLAN/firewall)', 'Принцип минимальных привилегий', 'Мониторинг SSH-соединений', 'Двухфакторная аутентификация', 'Регулярный аудит authorized_keys'],
      en: ['Network segmentation (VLAN/firewall)', 'Principle of least privilege', 'SSH connection monitoring', 'Two-factor authentication', 'Regular authorized_keys audit'],
    },
    tools: ['UFW', 'auditd', 'Fail2Ban'],
  },
]

const SEVERITY_STYLE: Record<string, { badge: string; border: string; label: { ru: string; en: string } }> = {
  critical: { badge: 'bg-red-900/50 text-red-300 border-red-700', border: 'border-l-4 border-l-red-600', label: { ru: 'Критическая', en: 'Critical' } },
  high: { badge: 'bg-orange-900/50 text-orange-300 border-orange-700', border: 'border-l-4 border-l-orange-500', label: { ru: 'Высокая', en: 'High' } },
  medium: { badge: 'bg-yellow-900/50 text-yellow-300 border-yellow-700', border: 'border-l-4 border-l-yellow-500', label: { ru: 'Средняя', en: 'Medium' } },
}

export default function CyberAttacks() {
  const { lang } = useLang()
  const [expanded, setExpanded] = useState<string | null>(null)
  const [filter, setFilter] = useState('all')

  const filtered = ATTACKS.filter(a => filter === 'all' || a.severity === filter)

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Zap className="w-6 h-6 text-yellow-400" />
          {lang === 'ru' ? 'Анализ киберугроз' : 'Cyber Threat Analysis'}
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          {lang === 'ru'
            ? 'Современные кибератаки, методы обнаружения и требования к защите сервера'
            : 'Modern cyberattacks, detection methods and server protection requirements'}
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: lang === 'ru' ? 'Критических угроз' : 'Critical Threats', count: ATTACKS.filter(a => a.severity === 'critical').length, color: 'text-red-400', bg: 'bg-red-900/20 border-red-800' },
          { label: lang === 'ru' ? 'Высоких угроз' : 'High Threats', count: ATTACKS.filter(a => a.severity === 'high').length, color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-800' },
          { label: lang === 'ru' ? 'Всего в каталоге' : 'Total in catalog', count: ATTACKS.length, color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-800' },
        ].map(c => (
          <div key={c.label} className={`${c.bg} border rounded-xl p-4 text-center`}>
            <div className={`text-3xl font-bold ${c.color}`}>{c.count}</div>
            <div className="text-xs text-gray-400 mt-1">{c.label}</div>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div className="flex gap-2">
        {['all', 'critical', 'high'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
              filter === f ? 'bg-blue-600 border-blue-500 text-white' : 'bg-gray-900 border-gray-700 text-gray-400 hover:text-white'
            }`}>
            {f === 'all' ? (lang === 'ru' ? 'Все' : 'All')
              : f === 'critical' ? (lang === 'ru' ? 'Критические' : 'Critical')
              : (lang === 'ru' ? 'Высокие' : 'High')}
          </button>
        ))}
      </div>

      {/* Attacks list */}
      <div className="space-y-3">
        {filtered.map(attack => (
          <div key={attack.id} className={`bg-gray-900 border border-gray-800 ${SEVERITY_STYLE[attack.severity].border} rounded-xl overflow-hidden`}>
            <button className="w-full p-5 text-left"
              onClick={() => setExpanded(expanded === attack.id ? null : attack.id)}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <span className="text-2xl">{attack.icon}</span>
                  <div>
                    <div className="font-bold text-white">{attack.name[lang]}</div>
                    <div className="text-xs text-gray-400 mt-0.5 line-clamp-1">{attack.description[lang]}</div>
                  </div>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <span className={`text-xs px-2 py-0.5 rounded border ${SEVERITY_STYLE[attack.severity].badge}`}>
                    {SEVERITY_STYLE[attack.severity].label[lang]}
                  </span>
                  {expanded === attack.id ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
                </div>
              </div>
            </button>

            {expanded === attack.id && (
              <div className="px-5 pb-5 space-y-4 border-t border-gray-800 pt-4">
                <p className="text-sm text-gray-300">{attack.description[lang]}</p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Indicators */}
                  <div className="bg-gray-800/50 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-3">
                      <AlertTriangle className="w-4 h-4 text-yellow-400" />
                      <span className="text-sm font-medium text-yellow-400">
                        {lang === 'ru' ? 'Признаки атаки:' : 'Attack indicators:'}
                      </span>
                    </div>
                    <ul className="space-y-1.5">
                      {attack.indicators[lang].map((ind, i) => (
                        <li key={i} className="text-xs text-gray-300 flex items-start gap-2">
                          <span className="text-yellow-500 mt-0.5">•</span>{ind}
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Prevention */}
                  <div className="bg-gray-800/50 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-3">
                      <Shield className="w-4 h-4 text-green-400" />
                      <span className="text-sm font-medium text-green-400">
                        {lang === 'ru' ? 'Меры защиты:' : 'Prevention measures:'}
                      </span>
                    </div>
                    <ul className="space-y-1.5">
                      {attack.prevention[lang].map((p, i) => (
                        <li key={i} className="text-xs text-gray-300 flex items-start gap-2">
                          <CheckCircle className="w-3 h-3 text-green-500 mt-0.5 flex-shrink-0" />{p}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Tools */}
                <div>
                  <span className="text-xs text-gray-500 mr-2">
                    {lang === 'ru' ? 'Рекомендуемые инструменты:' : 'Recommended tools:'}
                  </span>
                  {attack.tools.map(tool => (
                    <span key={tool} className="inline-block mr-1.5 mb-1 text-xs bg-blue-900/30 text-blue-300 border border-blue-800/50 px-2 py-0.5 rounded">
                      {tool}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
