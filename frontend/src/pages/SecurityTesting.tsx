import { useState } from 'react'
import { Target, CheckCircle, XCircle, AlertTriangle, Play, Terminal, ChevronDown, ChevronUp, Clock, Shield } from 'lucide-react'
import { useLang } from '../i18n'
import { scansApi } from '../api'

// ─── SIMULATION TESTS ────────────────────────────────────────────────────────
// Each test checks real server config without sending actual attacks.
// It reads settings and determines if the server WOULD be vulnerable.

const SIMULATIONS = [
  {
    id: 'sim_ssh_bruteforce',
    name: { ru: 'Брутфорс SSH', en: 'SSH Brute Force' },
    icon: '🔓',
    category: 'bruteforce',
    description: {
      ru: 'Проверяет, защищён ли SSH от перебора паролей: лимит попыток, Fail2Ban, отключение парольной аутентификации.',
      en: 'Checks if SSH is protected against password guessing: attempt limits, Fail2Ban, password authentication disabled.',
    },
    checks: ['ssh_max_auth', 'ssh_password_auth', 'sys_fail2ban'],
    risk: {
      ru: 'Без защиты сервер взламывается за часы с помощью Hydra/Medusa',
      en: 'Without protection, the server can be cracked in hours using Hydra/Medusa',
    },
  },
  {
    id: 'sim_ddos',
    name: { ru: 'DDoS / SYN Flood', en: 'DDoS / SYN Flood' },
    icon: '🌊',
    category: 'ddos',
    description: {
      ru: 'Проверяет защиту от SYN-flood и исчерпания ресурсов: TCP SYN cookies, ограничения соединений, UFW.',
      en: 'Checks protection against SYN-flood and resource exhaustion: TCP SYN cookies, connection limits, UFW.',
    },
    checks: ['net_syncookies', 'net_firewall', 'net_ip_forward'],
    risk: {
      ru: 'Без SYN cookies сервер падает от ~10k SYN-пакетов в секунду',
      en: 'Without SYN cookies, the server crashes from ~10k SYN packets per second',
    },
  },
  {
    id: 'sim_privilege_esc',
    name: { ru: 'Повышение привилегий', en: 'Privilege Escalation' },
    icon: '⬆️',
    category: 'exploitation',
    description: {
      ru: 'Ищет SUID-файлы, слабые sudo-правила и отключённые механизмы MAC (AppArmor), через которые можно получить root.',
      en: 'Looks for SUID files, weak sudo rules and disabled MAC mechanisms (AppArmor) that could lead to root access.',
    },
    checks: ['sys_suid', 'sys_apparmor', 'sys_updates'],
    risk: {
      ru: 'Атакующий с shell-доступом может стать root за минуты',
      en: 'Attacker with shell access can become root in minutes',
    },
  },
  {
    id: 'sim_unpatched_cve',
    name: { ru: 'Эксплуатация CVE', en: 'CVE Exploitation' },
    icon: '💣',
    category: 'exploitation',
    description: {
      ru: 'Проверяет наличие неустановленных обновлений безопасности, которые закрывают публично известные уязвимости.',
      en: 'Checks for missing security updates that fix publicly known vulnerabilities.',
    },
    checks: ['sys_updates', 'sys_unattended_upgrades'],
    risk: {
      ru: 'Известные CVE (Dirty COW, PwnKit и др.) эксплуатируются автоматически',
      en: 'Known CVEs (Dirty COW, PwnKit etc.) are exploited automatically',
    },
  },
  {
    id: 'sim_lateral_movement',
    name: { ru: 'Lateral Movement', en: 'Lateral Movement' },
    icon: '🔄',
    category: 'persistence',
    description: {
      ru: 'Проверяет, может ли скомпрометированный сервер стать плацдармом для атаки на соседние хосты через IP forwarding и открытые порты.',
      en: 'Checks if a compromised server can become a pivot point to attack neighboring hosts via IP forwarding and open ports.',
    },
    checks: ['net_ip_forward', 'net_open_ports', 'net_firewall'],
    risk: {
      ru: 'IP forwarding + открытый Redis/MySQL = доступ ко всей внутренней сети',
      en: 'IP forwarding + open Redis/MySQL = access to entire internal network',
    },
  },
  {
    id: 'sim_rootkit',
    name: { ru: 'Rootkit / Persistence', en: 'Rootkit / Persistence' },
    icon: '👻',
    category: 'persistence',
    description: {
      ru: 'Проверяет наличие auditd и целостность системных файлов — основных защит от закрепления вредоносного кода.',
      en: 'Checks for auditd and system file integrity — the main defenses against malicious code persistence.',
    },
    checks: ['sys_auditd', 'sys_apparmor'],
    risk: {
      ru: 'Без auditd rootkit незаметно работает годами',
      en: 'Without auditd, rootkit works undetected for years',
    },
  },
  {
    id: 'sim_web_shell',
    name: { ru: 'Веб-шелл / RCE', en: 'Web Shell / RCE' },
    icon: '🕷️',
    category: 'exploitation',
    description: {
      ru: 'Проверяет изоляцию веб-процессов через AppArmor и наличие аудита файловых операций для обнаружения загруженных шеллов.',
      en: 'Checks web process isolation via AppArmor and file operation auditing to detect uploaded shells.',
    },
    checks: ['sys_apparmor', 'sys_auditd', 'sys_tmp_noexec'],
    risk: {
      ru: 'Загруженный PHP-шелл даёт полный контроль над сервером',
      en: 'Uploaded PHP shell gives full control over the server',
    },
  },
  {
    id: 'sim_mitm',
    name: { ru: 'MITM / Перехват трафика', en: 'MITM / Traffic Interception' },
    icon: '👥',
    category: 'network',
    description: {
      ru: 'Проверяет стойкость шифрования SSH и наличие защиты от перехвата сетевых соединений.',
      en: 'Checks SSH encryption strength and protection against network connection interception.',
    },
    checks: ['crypto_ciphers', 'crypto_macs', 'ssh_protocol'],
    risk: {
      ru: 'Слабые алгоритмы SSH позволяют расшифровать сессию в реальном времени',
      en: 'Weak SSH algorithms allow real-time session decryption',
    },
  },
]

// ─── PENTEST CHECKLIST ────────────────────────────────────────────────────────

const PENTEST_ITEMS = [
  {
    phase: { ru: '1. Разведка (Reconnaissance)', en: '1. Reconnaissance' },
    color: 'border-blue-700 bg-blue-900/10',
    phaseColor: 'text-blue-400',
    items: [
      {
        id: 'p1', name: { ru: 'Сканирование портов Nmap', en: 'Nmap Port Scan' },
        cmd: 'nmap -sV -sC -O -p- --min-rate 1000 TARGET_IP',
        desc: { ru: 'Определяет открытые порты, версии сервисов и ОС', en: 'Identifies open ports, service versions and OS' },
        risk: 'medium',
      },
      {
        id: 'p2', name: { ru: 'Скрытое сканирование (SYN)', en: 'Stealth Scan (SYN)' },
        cmd: 'sudo nmap -sS -T4 -Pn TARGET_IP',
        desc: { ru: 'SYN-сканирование не оставляет записей в логах приложений', en: 'SYN scan leaves no records in application logs' },
        risk: 'medium',
      },
      {
        id: 'p3', name: { ru: 'Проверка баннеров сервисов', en: 'Service Banner Grabbing' },
        cmd: 'nc -v TARGET_IP 22\nnc -v TARGET_IP 80\nnc -v TARGET_IP 21',
        desc: { ru: 'Определяет версии ПО для поиска CVE', en: 'Identifies software versions to find CVEs' },
        risk: 'low',
      },
    ],
  },
  {
    phase: { ru: '2. Анализ аутентификации', en: '2. Authentication Analysis' },
    color: 'border-yellow-700 bg-yellow-900/10',
    phaseColor: 'text-yellow-400',
    items: [
      {
        id: 'p4', name: { ru: 'Проверка SSH root-логина', en: 'SSH Root Login Check' },
        cmd: 'ssh root@TARGET_IP -o PasswordAuthentication=yes 2>&1 | grep -i "permission\\|denied\\|password"',
        desc: { ru: 'Проверяет разрешён ли вход root по SSH', en: 'Checks if root SSH login is permitted' },
        risk: 'high',
      },
      {
        id: 'p5', name: { ru: 'Тест пустых паролей', en: 'Empty Password Test' },
        cmd: 'ssh -o PasswordAuthentication=yes -o BatchMode=no user@TARGET_IP',
        desc: { ru: 'Проверяет аккаунты с пустыми паролями', en: 'Tests accounts with empty passwords' },
        risk: 'critical',
      },
      {
        id: 'p6', name: { ru: 'Проверка дефолтных учётных данных', en: 'Default Credentials Check' },
        cmd: '# Проверить вручную: admin:admin, root:root, admin:password\nssh admin@TARGET_IP\nssh root@TARGET_IP',
        desc: { ru: 'Часто забывают сменить дефолтные пароли', en: 'Default passwords are often left unchanged' },
        risk: 'critical',
      },
    ],
  },
  {
    phase: { ru: '3. Проверка сети и фаервола', en: '3. Network & Firewall Check' },
    color: 'border-orange-700 bg-orange-900/10',
    phaseColor: 'text-orange-400',
    items: [
      {
        id: 'p7', name: { ru: 'Проверка UFW статуса', en: 'UFW Status Check' },
        cmd: 'sudo ufw status verbose',
        desc: { ru: 'Проверяет активность фаервола и правила', en: 'Checks firewall activity and rules' },
        risk: 'high',
      },
      {
        id: 'p8', name: { ru: 'Открытые сервисы наружу', en: 'Exposed Services Check' },
        cmd: 'ss -tlnp | grep -E "0.0.0.0|::"\nnmap -sV TARGET_IP -p 3306,5432,6379,27017,8080,8443',
        desc: { ru: 'БД и внутренние сервисы не должны быть доступны извне', en: 'DBs and internal services should not be externally accessible' },
        risk: 'critical',
      },
      {
        id: 'p9', name: { ru: 'IP Forwarding проверка', en: 'IP Forwarding Check' },
        cmd: 'cat /proc/sys/net/ipv4/ip_forward\nsysctl net.ipv4.ip_forward',
        desc: { ru: 'IP Forwarding = сервер как маршрутизатор для атакующего', en: 'IP Forwarding = server as router for attacker' },
        risk: 'medium',
      },
    ],
  },
  {
    phase: { ru: '4. Повышение привилегий', en: '4. Privilege Escalation' },
    color: 'border-red-700 bg-red-900/10',
    phaseColor: 'text-red-400',
    items: [
      {
        id: 'p10', name: { ru: 'SUID файлы', en: 'SUID Files' },
        cmd: 'find / -perm -4000 -type f 2>/dev/null\n# Проверить на GTFOBins: https://gtfobins.github.io',
        desc: { ru: 'SUID файлы могут использоваться для получения root', en: 'SUID files can be used to gain root access' },
        risk: 'high',
      },
      {
        id: 'p11', name: { ru: 'Sudo-привилегии', en: 'Sudo Privileges' },
        cmd: 'sudo -l\ncat /etc/sudoers 2>/dev/null',
        desc: { ru: 'Широкие sudo-права = прямой путь к root', en: 'Broad sudo rights = direct path to root' },
        risk: 'critical',
      },
      {
        id: 'p12', name: { ru: 'World-writable файлы', en: 'World-Writable Files' },
        cmd: 'find / -writable -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null | head -20',
        desc: { ru: 'Файлы доступные для записи всем — вектор атаки', en: 'Files writable by everyone — attack vector' },
        risk: 'medium',
      },
    ],
  },
  {
    phase: { ru: '5. Аудит логов и обнаружение', en: '5. Log Audit & Detection' },
    color: 'border-purple-700 bg-purple-900/10',
    phaseColor: 'text-purple-400',
    items: [
      {
        id: 'p13', name: { ru: 'Проверка auditd', en: 'Auditd Check' },
        cmd: 'systemctl is-active auditd\nauditctl -l\naudit_status=$(auditctl -s)',
        desc: { ru: 'Без auditd невозможно расследовать инциденты', en: 'Without auditd, incident investigation is impossible' },
        risk: 'high',
      },
      {
        id: 'p14', name: { ru: 'Анализ auth.log', en: 'Auth Log Analysis' },
        cmd: 'grep "Failed password" /var/log/auth.log | tail -20\ngrep "Accepted" /var/log/auth.log | tail -10\nlastlog | grep -v "Never"',
        desc: { ru: 'История успешных и неудачных входов', en: 'History of successful and failed logins' },
        risk: 'medium',
      },
      {
        id: 'p15', name: { ru: 'Проверка Fail2Ban', en: 'Fail2Ban Check' },
        cmd: 'systemctl is-active fail2ban\nsudo fail2ban-client status\nsudo fail2ban-client status sshd',
        desc: { ru: 'Fail2Ban должен быть активен и блокировать IP', en: 'Fail2Ban must be active and blocking IPs' },
        risk: 'high',
      },
    ],
  },
]

const RISK_STYLE: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/20 border-red-800',
  high: 'text-orange-400 bg-orange-900/20 border-orange-800',
  medium: 'text-yellow-400 bg-yellow-900/20 border-yellow-800',
  low: 'text-blue-400 bg-blue-900/20 border-blue-800',
}

// ─── COMPONENT ────────────────────────────────────────────────────────────────

export default function SecurityTesting() {
  const { lang } = useLang()
  const [tab, setTab] = useState<'simulation' | 'pentest'>('simulation')
  const [simResults, setSimResults] = useState<Record<string, 'running' | 'done'>>({})
  const [simScores, setSimScores] = useState<Record<string, { vulnerable: boolean; checks: any[] }>>({})
  const [lastScanFindings, setLastScanFindings] = useState<any[]>([])
  const [loadingAll, setLoadingAll] = useState(false)
  const [checkedItems, setCheckedItems] = useState<Set<string>>(new Set())
  const [expandedPhase, setExpandedPhase] = useState<string | null>(null)
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null)

  const loadFindings = async () => {
    try {
      const scans = await scansApi.list()
      const completed = scans.data.find((s: any) => s.status === 'completed')
      if (completed) {
        const detail = await scansApi.get(completed.id)
        return detail.data.findings || []
      }
    } catch {}
    return []
  }

  const runSimulation = async (simId: string) => {
    setSimResults(r => ({ ...r, [simId]: 'running' }))
    let findings = lastScanFindings
    if (findings.length === 0) {
      findings = await loadFindings()
      setLastScanFindings(findings)
    }
    const sim = SIMULATIONS.find(s => s.id === simId)!
    const relevant = findings.filter((f: any) => sim.checks.includes(f.check_id))
    const vulnerable = relevant.some((f: any) => f.status === 'fail') || relevant.length === 0
    setTimeout(() => {
      setSimResults(r => ({ ...r, [simId]: 'done' }))
      setSimScores(s => ({ ...s, [simId]: { vulnerable, checks: relevant } }))
    }, 800 + Math.random() * 600)
  }

  const runAllSimulations = async () => {
    setLoadingAll(true)
    const findings = await loadFindings()
    setLastScanFindings(findings)
    for (const sim of SIMULATIONS) {
      setSimResults(r => ({ ...r, [sim.id]: 'running' }))
    }
    await new Promise(r => setTimeout(r, 400))
    for (const sim of SIMULATIONS) {
      const relevant = findings.filter((f: any) => sim.checks.includes(f.check_id))
      const vulnerable = relevant.some((f: any) => f.status === 'fail') || relevant.length === 0
      setSimResults(r => ({ ...r, [sim.id]: 'done' }))
      setSimScores(s => ({ ...s, [sim.id]: { vulnerable, checks: relevant } }))
      await new Promise(r => setTimeout(r, 150))
    }
    setLoadingAll(false)
  }

  const toggleCheck = (id: string) => {
    setCheckedItems(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const copyCmd = (cmd: string, id: string) => {
    navigator.clipboard.writeText(cmd)
    setCopiedCmd(id)
    setTimeout(() => setCopiedCmd(null), 1500)
  }

  const doneCount = Object.values(simResults).filter(v => v === 'done').length
  const vulnerableCount = Object.values(simScores).filter(s => s.vulnerable).length
  const safeCount = Object.values(simScores).filter(s => !s.vulnerable).length
  const totalChecked = checkedItems.size
  const totalPentestItems = PENTEST_ITEMS.reduce((sum, p) => sum + p.items.length, 0)

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Target className="w-6 h-6 text-red-400" />
          {lang === 'ru' ? 'Тестирование защиты' : 'Security Testing'}
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          {lang === 'ru'
            ? 'Симуляция уязвимостей на основе текущих настроек + чеклист ручного пентеста'
            : 'Vulnerability simulation based on current settings + manual pentest checklist'}
        </p>
        <div className="mt-2 flex items-center gap-2 text-xs text-yellow-400 bg-yellow-900/20 border border-yellow-800/50 rounded-lg px-3 py-2 w-fit">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
          {lang === 'ru'
            ? 'Симуляция читает конфигурацию сервера — реальных атак не проводится. Команды в чеклисте запускайте только на своих системах.'
            : 'Simulation reads server configuration — no real attacks are performed. Only run checklist commands on your own systems.'}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900 border border-gray-800 rounded-xl p-1 w-fit">
        <button onClick={() => setTab('simulation')}
          className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${tab === 'simulation' ? 'bg-red-700 text-white shadow-md' : 'text-gray-400 hover:text-white'}`}>
          {lang === 'ru' ? '⚡ Симуляция атак' : '⚡ Attack Simulation'}
        </button>
        <button onClick={() => setTab('pentest')}
          className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${tab === 'pentest' ? 'bg-blue-700 text-white shadow-md' : 'text-gray-400 hover:text-white'}`}>
          {lang === 'ru' ? '📋 Pentest Checklist' : '📋 Pentest Checklist'}
        </button>
      </div>

      {/* ── SIMULATION TAB ── */}
      {tab === 'simulation' && (
        <div className="space-y-4">
          {/* Summary + run all */}
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex gap-3">
              {doneCount > 0 && <>
                <div className="flex items-center gap-2 bg-red-900/20 border border-red-800 rounded-lg px-3 py-1.5 text-sm">
                  <XCircle className="w-4 h-4 text-red-400" />
                  <span className="text-red-300 font-medium">{vulnerableCount}</span>
                  <span className="text-gray-400">{lang === 'ru' ? 'уязвимых' : 'vulnerable'}</span>
                </div>
                <div className="flex items-center gap-2 bg-green-900/20 border border-green-800 rounded-lg px-3 py-1.5 text-sm">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-green-300 font-medium">{safeCount}</span>
                  <span className="text-gray-400">{lang === 'ru' ? 'защищённых' : 'protected'}</span>
                </div>
              </>}
            </div>
            <button onClick={runAllSimulations} disabled={loadingAll}
              className="flex items-center gap-2 bg-gradient-to-r from-red-700 to-red-800 hover:from-red-600 hover:to-red-700 disabled:opacity-60 text-white px-5 py-2.5 rounded-xl text-sm font-medium shadow-lg shadow-red-900/30 transition-all">
              {loadingAll ? <Clock className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {lang === 'ru' ? 'Запустить все симуляции' : 'Run All Simulations'}
            </button>
          </div>

          {/* Hint if no scan data */}
          {doneCount === 0 && (
            <div className="bg-blue-900/20 border border-blue-800/50 rounded-xl p-4 text-sm text-blue-300 flex items-start gap-2">
              <Shield className="w-4 h-4 mt-0.5 flex-shrink-0" />
              {lang === 'ru'
                ? 'Для точных результатов сначала выполните сканирование на вкладке "Сканирования", затем запустите симуляции.'
                : 'For accurate results, first run a scan on the "Scans" tab, then launch simulations.'}
            </div>
          )}

          {/* Simulations grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {SIMULATIONS.map(sim => {
              const result = simResults[sim.id]
              const score = simScores[sim.id]
              return (
                <div key={sim.id} className={`bg-gray-900 border rounded-xl p-5 transition-all ${
                  score ? (score.vulnerable ? 'border-red-800/70' : 'border-green-800/70') : 'border-gray-800'
                }`}>
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">{sim.icon}</span>
                      <div>
                        <div className="font-semibold text-white text-sm">{sim.name[lang]}</div>
                        <div className="text-xs text-gray-500 mt-0.5">{sim.description[lang]}</div>
                      </div>
                    </div>
                    {result === 'running' ? (
                      <Clock className="w-5 h-5 text-blue-400 animate-spin flex-shrink-0 mt-0.5" />
                    ) : score ? (
                      score.vulnerable
                        ? <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                        : <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    ) : null}
                  </div>

                  {score && (
                    <div className={`rounded-lg px-3 py-2 text-xs mb-3 ${score.vulnerable ? 'bg-red-900/30 border border-red-800 text-red-300' : 'bg-green-900/30 border border-green-800 text-green-300'}`}>
                      {score.vulnerable
                        ? `⚠ ${lang === 'ru' ? 'УЯЗВИМ: ' : 'VULNERABLE: '}${sim.risk[lang]}`
                        : `✓ ${lang === 'ru' ? 'Защищён от данной атаки' : 'Protected against this attack'}`}
                    </div>
                  )}

                  <button onClick={() => runSimulation(sim.id)} disabled={result === 'running'}
                    className="w-full text-xs py-2 rounded-lg border transition-colors disabled:opacity-50 border-gray-700 text-gray-400 hover:bg-gray-800 hover:text-white flex items-center justify-center gap-1.5">
                    {result === 'running'
                      ? <><Clock className="w-3 h-3 animate-spin" />{lang === 'ru' ? 'Анализ...' : 'Analyzing...'}</>
                      : <><Play className="w-3 h-3" />{lang === 'ru' ? 'Симулировать' : 'Simulate'}</>}
                  </button>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── PENTEST CHECKLIST TAB ── */}
      {tab === 'pentest' && (
        <div className="space-y-4">
          {/* Progress */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-center gap-4">
            <div className="flex-1">
              <div className="flex justify-between text-xs text-gray-400 mb-1.5">
                <span>{lang === 'ru' ? 'Прогресс проверки' : 'Check Progress'}</span>
                <span>{totalChecked} / {totalPentestItems}</span>
              </div>
              <div className="bg-gray-800 rounded-full h-2">
                <div className="bg-blue-500 h-2 rounded-full transition-all"
                  style={{ width: `${(totalChecked / totalPentestItems) * 100}%` }} />
              </div>
            </div>
            <button onClick={() => setCheckedItems(new Set())}
              className="text-xs text-gray-500 hover:text-gray-300 px-3 py-1.5 border border-gray-700 rounded-lg transition-colors">
              {lang === 'ru' ? 'Сбросить' : 'Reset'}
            </button>
          </div>

          {/* Phases */}
          <div className="space-y-3">
            {PENTEST_ITEMS.map(phase => {
              const phaseChecked = phase.items.filter(i => checkedItems.has(i.id)).length
              const isOpen = expandedPhase === phase.phase.ru

              return (
                <div key={phase.phase.ru} className={`border rounded-xl overflow-hidden ${phase.color}`}>
                  <button className="w-full p-4 text-left flex items-center justify-between"
                    onClick={() => setExpandedPhase(isOpen ? null : phase.phase.ru)}>
                    <div className="flex items-center gap-3">
                      <span className={`font-semibold ${phase.phaseColor}`}>{phase.phase[lang]}</span>
                      <span className="text-xs text-gray-500">{phaseChecked}/{phase.items.length} {lang === 'ru' ? 'выполнено' : 'done'}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-gray-800 rounded-full h-1.5">
                        <div className={`h-1.5 rounded-full transition-all`}
                          style={{ width: `${(phaseChecked / phase.items.length) * 100}%`, background: phase.phaseColor.replace('text-', '#').includes('#') ? '#60a5fa' : '#60a5fa' }} />
                      </div>
                      {isOpen ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
                    </div>
                  </button>

                  {isOpen && (
                    <div className="divide-y divide-gray-800/50">
                      {phase.items.map(item => (
                        <div key={item.id} className={`p-4 transition-colors ${checkedItems.has(item.id) ? 'bg-green-900/10' : ''}`}>
                          <div className="flex items-start gap-3">
                            <input type="checkbox" checked={checkedItems.has(item.id)}
                              onChange={() => toggleCheck(item.id)}
                              className="mt-0.5 w-4 h-4 accent-green-500 cursor-pointer flex-shrink-0" />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1 flex-wrap">
                                <span className={`font-medium text-sm ${checkedItems.has(item.id) ? 'text-gray-500 line-through' : 'text-white'}`}>
                                  {item.name[lang]}
                                </span>
                                <span className={`text-xs px-1.5 py-0.5 rounded border ${RISK_STYLE[item.risk]}`}>
                                  {item.risk}
                                </span>
                              </div>
                              <p className="text-xs text-gray-400 mb-2">{item.desc[lang]}</p>
                              <div className="relative">
                                <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs text-green-300 font-mono overflow-x-auto whitespace-pre">
                                  {item.cmd}
                                </pre>
                                <button
                                  onClick={() => copyCmd(item.cmd, item.id)}
                                  className="absolute top-2 right-2 text-xs bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white px-2 py-0.5 rounded transition-colors">
                                  {copiedCmd === item.id ? '✓' : (lang === 'ru' ? 'Копировать' : 'Copy')}
                                </button>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
