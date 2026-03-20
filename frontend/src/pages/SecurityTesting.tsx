import { useState } from 'react'
import { Target, CheckCircle, XCircle, AlertTriangle, Play, Terminal,
         ChevronDown, ChevronUp, Clock, Shield, RefreshCw, Download } from 'lucide-react'
import axios from 'axios'
import { useLang } from '../i18n'

const api = axios.create({ baseURL: '/api' })
api.interceptors.request.use(c => {
  const t = localStorage.getItem('access_token')
  if (t) c.headers.Authorization = `Bearer ${t}`
  return c
})

// ─── Real attack simulations - each runs actual system checks ─────────────

const SIMULATIONS = [
  {
    id: 'sim_bruteforce',
    name: { ru: 'Брутфорс SSH', en: 'SSH Brute Force' },
    icon: '🔓',
    description: {
      ru: 'Проверяет реальную защиту: MaxAuthTries, Fail2Ban правила, парольная аутентификация, пустые пароли.',
      en: 'Checks real protection: MaxAuthTries, Fail2Ban rules, password auth, empty passwords.',
    },
    // Each check is a shell command + expected result
    real_checks: [
      { label: 'MaxAuthTries ≤ 4', cmd: "grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'", expect: (v:string) => { const n=parseInt(v); return n>0 && n<=4 }, fix: 'sed -i "s/^#*MaxAuthTries.*/MaxAuthTries 4/" /etc/ssh/sshd_config && systemctl restart sshd' },
      { label: 'PasswordAuthentication no', cmd: "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'", expect: (v:string) => v.toLowerCase()==='no', fix: 'sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config && systemctl restart sshd' },
      { label: 'Fail2Ban активен', cmd: 'systemctl is-active fail2ban 2>/dev/null', expect: (v:string) => v.trim()==='active', fix: 'apt-get install -y fail2ban && systemctl enable --now fail2ban' },
      { label: 'Нет пустых паролей', cmd: "awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null | wc -l", expect: (v:string) => parseInt(v)===0, fix: 'passwd -l $(awk -F: \'($2 == "") {print $1}\' /etc/shadow)' },
      { label: 'PermitRootLogin no', cmd: "grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'", expect: (v:string) => v.toLowerCase()==='no', fix: 'sed -i "s/^#*PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config && systemctl restart sshd' },
    ],
  },
  {
    id: 'sim_ddos',
    name: { ru: 'DDoS / SYN Flood', en: 'DDoS / SYN Flood' },
    icon: '🌊',
    description: {
      ru: 'Проверяет TCP SYN cookies, ограничения соединений, активность фаервола и rate limiting.',
      en: 'Checks TCP SYN cookies, connection limits, firewall activity and rate limiting.',
    },
    real_checks: [
      { label: 'SYN cookies включены', cmd: 'sysctl -n net.ipv4.tcp_syncookies 2>/dev/null', expect: (v:string) => v.trim()==='1', fix: 'sysctl -w net.ipv4.tcp_syncookies=1 && echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf' },
      { label: 'Фаервол активен', cmd: 'ufw status 2>/dev/null | head -1', expect: (v:string) => v.toLowerCase().includes('active'), fix: 'ufw --force enable' },
      { label: 'IP Forwarding выключен', cmd: 'sysctl -n net.ipv4.ip_forward 2>/dev/null', expect: (v:string) => v.trim()==='0', fix: 'sysctl -w net.ipv4.ip_forward=0' },
      { label: 'ICMP redirects отключены', cmd: 'sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null', expect: (v:string) => v.trim()==='0', fix: 'sysctl -w net.ipv4.conf.all.accept_redirects=0' },
      { label: 'Нет опасных открытых портов', cmd: 'ss -tlnp 2>/dev/null | grep -cE ":(6379|27017|9200|11211)\\b" || echo 0', expect: (v:string) => parseInt(v)===0, fix: 'ufw deny 6379 && ufw deny 27017 && ufw deny 9200' },
    ],
  },
  {
    id: 'sim_privesc',
    name: { ru: 'Повышение привилегий', en: 'Privilege Escalation' },
    icon: '⬆️',
    description: {
      ru: 'Ищет реальные SUID файлы, слабые sudo-правила, отключённый AppArmor — реальные векторы атаки.',
      en: 'Finds real SUID files, weak sudo rules, disabled AppArmor — real attack vectors.',
    },
    real_checks: [
      { label: 'SUID файлов < 15', cmd: 'find / -perm -4000 -type f 2>/dev/null | grep -v "/proc\\|/snap" | wc -l', expect: (v:string) => parseInt(v)<15, fix: 'find / -perm -4000 -type f 2>/dev/null | grep -v "/proc|/snap" | xargs ls -la' },
      { label: 'AppArmor активен', cmd: 'systemctl is-active apparmor 2>/dev/null', expect: (v:string) => v.trim()==='active', fix: 'apt-get install -y apparmor apparmor-utils && systemctl enable --now apparmor' },
      { label: 'Нет world-writable системных файлов', cmd: 'find /etc /bin /usr/bin -perm -o+w -type f 2>/dev/null | wc -l', expect: (v:string) => parseInt(v)===0, fix: 'find /etc /bin /usr/bin -perm -o+w -type f 2>/dev/null | xargs chmod o-w' },
      { label: 'Только root с UID 0', cmd: "awk -F: '($3==0){print $1}' /etc/passwd | grep -v '^root$' | wc -l", expect: (v:string) => parseInt(v)===0, fix: 'Проверьте вручную: awk -F: \'($3==0)\' /etc/passwd' },
      { label: 'Обновления системы', cmd: 'apt-get -s upgrade 2>/dev/null | grep -c "^Inst" || echo 0', expect: (v:string) => parseInt(v)<5, fix: 'apt-get update && apt-get upgrade -y' },
    ],
  },
  {
    id: 'sim_persistence',
    name: { ru: 'Бэкдор / Persistence', en: 'Backdoor / Persistence' },
    icon: '👻',
    description: {
      ru: 'Проверяет подозрительные cron задачи, systemd юниты, незнакомые процессы и SSH authorized_keys.',
      en: 'Checks suspicious cron jobs, systemd units, unknown processes and SSH authorized_keys.',
    },
    real_checks: [
      { label: 'Auditd активен', cmd: 'systemctl is-active auditd 2>/dev/null', expect: (v:string) => v.trim()==='active', fix: 'apt-get install -y auditd && systemctl enable --now auditd' },
      { label: 'Нет подозрительных cron задач', cmd: 'crontab -l 2>/dev/null | grep -cvE "^#|^$" || echo 0', expect: (v:string) => parseInt(v)===0, fix: 'crontab -l # Проверьте вручную список cron задач' },
      { label: 'Права /etc/crontab = 600', cmd: 'stat -c %a /etc/crontab 2>/dev/null', expect: (v:string) => ['600','400'].includes(v.trim()), fix: 'chmod 600 /etc/crontab && chown root:root /etc/crontab' },
      { label: 'Нет посторонних authorized_keys у root', cmd: 'cat /root/.ssh/authorized_keys 2>/dev/null | grep -v "^#\\|^$" | wc -l', expect: (v:string) => parseInt(v)===0, fix: 'cat /root/.ssh/authorized_keys # Проверьте ключи вручную' },
      { label: 'rsyslog активен', cmd: 'systemctl is-active rsyslog 2>/dev/null', expect: (v:string) => v.trim()==='active', fix: 'apt-get install -y rsyslog && systemctl enable --now rsyslog' },
    ],
  },
  {
    id: 'sim_network',
    name: { ru: 'Сетевые уязвимости', en: 'Network Vulnerabilities' },
    icon: '🌐',
    description: {
      ru: 'Проверяет реальную сетевую конфигурацию: открытые порты, протоколы, сетевые параметры ядра.',
      en: 'Checks real network configuration: open ports, protocols, kernel network parameters.',
    },
    real_checks: [
      { label: 'SSH только Protocol 2', cmd: "grep -i '^Protocol' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'", expect: (v:string) => v.trim()==='' || v.trim()==='2', fix: 'echo "Protocol 2" >> /etc/ssh/sshd_config && systemctl restart sshd' },
      { label: 'Нет слабых SSH шифров', cmd: "grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null", expect: (v:string) => !v.includes('arcfour') && !v.includes('3des') && !v.includes('blowfish'), fix: 'echo "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com" >> /etc/ssh/sshd_config' },
      { label: 'Telnet не запущен', cmd: 'systemctl is-active telnet 2>/dev/null; systemctl is-active telnetd 2>/dev/null | head -1', expect: (v:string) => !v.includes('active') || v.includes('inactive'), fix: 'systemctl disable --now telnet telnetd 2>/dev/null; apt-get remove -y telnet' },
      { label: 'SSH таймаут настроен', cmd: "grep -i '^ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'", expect: (v:string) => { const n=parseInt(v); return n>0 && n<=600 }, fix: 'echo "ClientAliveInterval 300\nClientAliveCountMax 3" >> /etc/ssh/sshd_config' },
      { label: 'ASLR включён', cmd: 'sysctl -n kernel.randomize_va_space 2>/dev/null', expect: (v:string) => v.trim()==='2', fix: 'sysctl -w kernel.randomize_va_space=2 && echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf' },
    ],
  },
  {
    id: 'sim_crypto',
    name: { ru: 'Шифрование и TLS', en: 'Encryption & TLS' },
    icon: '🔐',
    description: {
      ru: 'Проверяет шифрование дисков, силу SSH криптографии и защиту передачи данных.',
      en: 'Checks disk encryption, SSH cryptography strength and data transmission security.',
    },
    real_checks: [
      { label: 'Сильные SSH MAC алгоритмы', cmd: "grep -i '^MACs' /etc/ssh/sshd_config 2>/dev/null", expect: (v:string) => !v.includes('hmac-md5') && !v.includes('hmac-sha1 '), fix: 'echo "MACs hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config' },
      { label: 'Swap зашифрован или отсутствует', cmd: "cat /proc/swaps 2>/dev/null | tail -n +2 | wc -l", expect: (v:string) => parseInt(v)===0, fix: 'Рассмотрите шифрование swap или его отключение: swapoff -a' },
      { label: 'Права /etc/shadow корректны', cmd: 'stat -c %a /etc/shadow 2>/dev/null', expect: (v:string) => ['640','600','400','000'].includes(v.trim()), fix: 'chmod 640 /etc/shadow && chown root:shadow /etc/shadow' },
      { label: 'Права /etc/passwd корректны', cmd: 'stat -c %a /etc/passwd 2>/dev/null', expect: (v:string) => ['644','444'].includes(v.trim()), fix: 'chmod 644 /etc/passwd' },
      { label: 'Минимальная длина пароля ≥ 12', cmd: "grep '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}'", expect: (v:string) => parseInt(v)>=12, fix: 'sed -i "s/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/" /etc/login.defs' },
    ],
  },
  {
    id: 'sim_webshell',
    name: { ru: 'Веб-шелл / RCE', en: 'Web Shell / RCE' },
    icon: '🕷️',
    description: {
      ru: 'Проверяет защиту веб-директорий, права на исполнение файлов, наличие изоляции веб-процессов.',
      en: 'Checks web directory protection, file execution rights, web process isolation.',
    },
    real_checks: [
      { label: '/tmp с флагом noexec', cmd: "mount | grep '/tmp' | grep -c noexec || cat /proc/mounts | grep ' /tmp ' | grep -c noexec || echo 0", expect: (v:string) => parseInt(v)>0, fix: 'echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab && mount -o remount /tmp' },
      { label: 'AppArmor защищает nginx/apache', cmd: 'aa-status 2>/dev/null | grep -cE "nginx|apache" || echo 0', expect: (v:string) => parseInt(v)>0, fix: 'aa-enforce /etc/apparmor.d/usr.sbin.nginx 2>/dev/null || apt-get install -y apparmor-profiles' },
      { label: 'Нет world-writable в /var/www', cmd: 'find /var/www 2>/dev/null -perm -o+w -type f | wc -l', expect: (v:string) => parseInt(v)===0, fix: 'find /var/www -perm -o+w -type f | xargs chmod o-w' },
      { label: 'Auditd мониторит /var/www', cmd: 'auditctl -l 2>/dev/null | grep -c "var/www" || echo 0', expect: (v:string) => parseInt(v)>0, fix: 'auditctl -w /var/www -p wa -k webshell' },
      { label: 'Sticky bit на /tmp', cmd: 'stat -c %a /tmp 2>/dev/null', expect: (v:string) => v.trim().startsWith('1'), fix: 'chmod +t /tmp' },
    ],
  },
  {
    id: 'sim_ransomware',
    name: { ru: 'Ransomware / Шифровальщик', en: 'Ransomware' },
    icon: '💀',
    description: {
      ru: 'Проверяет защиту от ransomware: бэкапы, изоляция, мониторинг файловой системы.',
      en: 'Checks ransomware protection: backups, isolation, file system monitoring.',
    },
    real_checks: [
      { label: 'Auditd мониторит изменения файлов', cmd: 'auditctl -l 2>/dev/null | grep -c "wa" || echo 0', expect: (v:string) => parseInt(v)>0, fix: 'auditctl -w /home -p wa -k ransomware && auditctl -w /var -p wa -k ransomware' },
      { label: 'AppArmor активен', cmd: 'systemctl is-active apparmor 2>/dev/null', expect: (v:string) => v.trim()==='active', fix: 'systemctl enable --now apparmor' },
      { label: 'ClamAV установлен', cmd: 'which clamscan 2>/dev/null | wc -l', expect: (v:string) => parseInt(v)>0, fix: 'apt-get install -y clamav clamav-daemon && freshclam' },
      { label: 'Нет подозрительных процессов шифрования', cmd: 'ps aux 2>/dev/null | grep -cE "(openssl enc|gpg --batch|cryptsetup)" | grep -v grep || echo 0', expect: (v:string) => parseInt(v)===0, fix: 'Проверьте процессы вручную: ps aux | grep crypt' },
      { label: 'Права на домашние директории', cmd: 'find /home -maxdepth 1 -type d -perm /o+rwx 2>/dev/null | wc -l', expect: (v:string) => parseInt(v)===0, fix: 'chmod 700 /home/*' },
    ],
  },
]

// ─── Pentest checklist ────────────────────────────────────────────────────

const PENTEST_ITEMS = [
  {
    phase: { ru: '1. Разведка (Reconnaissance)', en: '1. Reconnaissance' },
    color: 'border-blue-700 bg-blue-900/10', phaseColor: 'text-blue-400',
    items: [
      { id: 'p1', name: { ru: 'Сканирование портов Nmap', en: 'Nmap Port Scan' }, risk: 'medium',
        cmd: 'nmap -sV -sC -O -p- --min-rate 1000 TARGET_IP',
        desc: { ru: 'Определяет открытые порты, версии сервисов и ОС', en: 'Identifies open ports, service versions and OS' } },
      { id: 'p2', name: { ru: 'Скрытое SYN сканирование', en: 'Stealth SYN Scan' }, risk: 'medium',
        cmd: 'sudo nmap -sS -T4 -Pn TARGET_IP',
        desc: { ru: 'Не оставляет записей в логах приложений', en: 'Leaves no records in application logs' } },
      { id: 'p3', name: { ru: 'Захват баннеров', en: 'Banner Grabbing' }, risk: 'low',
        cmd: 'nc -v TARGET_IP 22 && nc -v TARGET_IP 80',
        desc: { ru: 'Версии ПО для поиска CVE', en: 'Software versions to find CVEs' } },
    ],
  },
  {
    phase: { ru: '2. Анализ аутентификации', en: '2. Authentication Analysis' },
    color: 'border-yellow-700 bg-yellow-900/10', phaseColor: 'text-yellow-400',
    items: [
      { id: 'p4', name: { ru: 'Проверка root SSH', en: 'Root SSH Check' }, risk: 'high',
        cmd: "grep -i 'PermitRootLogin' /etc/ssh/sshd_config",
        desc: { ru: 'Разрешён ли вход root по SSH?', en: 'Is root SSH login permitted?' } },
      { id: 'p5', name: { ru: 'Тест пустых паролей', en: 'Empty Password Test' }, risk: 'critical',
        cmd: "awk -F: '($2 == \"\") {print $1}' /etc/shadow",
        desc: { ru: 'Аккаунты без паролей', en: 'Accounts without passwords' } },
      { id: 'p6', name: { ru: 'Аккаунты с UID 0', en: 'UID 0 Accounts' }, risk: 'critical',
        cmd: "awk -F: '($3 == 0) {print $1}' /etc/passwd",
        desc: { ru: 'Только root должен иметь UID 0', en: 'Only root should have UID 0' } },
    ],
  },
  {
    phase: { ru: '3. Проверка сети', en: '3. Network Check' },
    color: 'border-orange-700 bg-orange-900/10', phaseColor: 'text-orange-400',
    items: [
      { id: 'p7', name: { ru: 'Статус фаервола', en: 'Firewall Status' }, risk: 'high',
        cmd: 'ufw status verbose',
        desc: { ru: 'Активность UFW и правила', en: 'UFW activity and rules' } },
      { id: 'p8', name: { ru: 'Опасные открытые порты', en: 'Dangerous Open Ports' }, risk: 'critical',
        cmd: 'ss -tlnp | grep -E ":(3306|5432|6379|27017|9200)"',
        desc: { ru: 'БД не должны быть доступны извне', en: 'DBs should not be externally accessible' } },
      { id: 'p9', name: { ru: 'IP Forwarding', en: 'IP Forwarding' }, risk: 'medium',
        cmd: 'sysctl net.ipv4.ip_forward',
        desc: { ru: 'Должен быть 0', en: 'Should be 0' } },
    ],
  },
  {
    phase: { ru: '4. Повышение привилегий', en: '4. Privilege Escalation' },
    color: 'border-red-700 bg-red-900/10', phaseColor: 'text-red-400',
    items: [
      { id: 'p10', name: { ru: 'SUID файлы', en: 'SUID Files' }, risk: 'high',
        cmd: 'find / -perm -4000 -type f 2>/dev/null | grep -v "/proc\\|/snap"',
        desc: { ru: 'Проверить через GTFOBins', en: 'Check via GTFOBins' } },
      { id: 'p11', name: { ru: 'Sudo привилегии', en: 'Sudo Privileges' }, risk: 'critical',
        cmd: 'sudo -l && cat /etc/sudoers 2>/dev/null',
        desc: { ru: 'Широкие sudo = путь к root', en: 'Broad sudo = path to root' } },
      { id: 'p12', name: { ru: 'World-writable файлы', en: 'World-Writable Files' }, risk: 'medium',
        cmd: 'find /etc /bin /usr -writable -type f 2>/dev/null',
        desc: { ru: 'Файлы доступные для записи всем', en: 'Files writable by everyone' } },
    ],
  },
  {
    phase: { ru: '5. Логи и обнаружение', en: '5. Logs & Detection' },
    color: 'border-purple-700 bg-purple-900/10', phaseColor: 'text-purple-400',
    items: [
      { id: 'p13', name: { ru: 'Статус auditd', en: 'Auditd Status' }, risk: 'high',
        cmd: 'systemctl is-active auditd && auditctl -l',
        desc: { ru: 'Без auditd нельзя расследовать инциденты', en: 'Without auditd incident investigation is impossible' } },
      { id: 'p14', name: { ru: 'Анализ auth.log', en: 'Auth Log Analysis' }, risk: 'medium',
        cmd: 'grep "Failed password" /var/log/auth.log | tail -20\ngrep "Accepted" /var/log/auth.log | tail -10',
        desc: { ru: 'История входов', en: 'Login history' } },
      { id: 'p15', name: { ru: 'Статус Fail2Ban', en: 'Fail2Ban Status' }, risk: 'high',
        cmd: 'systemctl is-active fail2ban && fail2ban-client status sshd',
        desc: { ru: 'Должен блокировать IP', en: 'Should be blocking IPs' } },
    ],
  },
]

const RISK_STYLE: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/20 border-red-800',
  high:     'text-orange-400 bg-orange-900/20 border-orange-800',
  medium:   'text-yellow-400 bg-yellow-900/20 border-yellow-800',
  low:      'text-blue-400 bg-blue-900/20 border-blue-800',
}

// ─── Component ────────────────────────────────────────────────────────────

interface CheckResult {
  label: string
  passed: boolean
  actual?: string
  fix?: string
}

interface SimResult {
  status: 'vulnerable' | 'protected' | 'partial'
  checks: CheckResult[]
  score: number
}

export default function SecurityTesting() {
  const { lang } = useLang()
  const [tab, setTab] = useState<'simulation' | 'pentest'>('simulation')
  const [running, setRunning] = useState<Record<string, boolean>>({})
  const [results, setResults] = useState<Record<string, SimResult>>({})
  const [runningAll, setRunningAll] = useState(false)
  const [checkedItems, setCheckedItems] = useState<Set<string>>(new Set())
  const [expandedPhase, setExpandedPhase] = useState<string | null>(null)
  const [expandedSim, setExpandedSim] = useState<string | null>(null)
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null)

  const runSim = async (simId: string) => {
    setRunning(r => ({ ...r, [simId]: true }))
    try {
      // Call backend to run real checks
      const res = await api.post('/os-scan/simulate', { sim_id: simId })
      setResults(r => ({ ...r, [simId]: res.data }))
    } catch {
      // Fallback: try scan endpoint
      try {
        const scanRes = await api.post('/scans/local')
        const findings = scanRes.data?.findings || []
        const sim = SIMULATIONS.find(s => s.id === simId)!
        // Map findings to check results
        const checks: CheckResult[] = sim.real_checks.map(c => {
          const found = findings.find((f: any) =>
            c.label.toLowerCase().includes(f.check_id?.split('_')[1] || '') ||
            f.name?.toLowerCase().includes(c.label.split(' ')[0].toLowerCase())
          )
          const passed = found ? found.status === 'pass' : false
          return { label: c.label, passed, actual: found?.current_value, fix: c.fix }
        })
        const passed = checks.filter(c => c.passed).length
        const score = Math.round((passed / checks.length) * 100)
        const status = score === 100 ? 'protected' : score >= 60 ? 'partial' : 'vulnerable'
        setResults(r => ({ ...r, [simId]: { status, checks, score } }))
      } catch {
        // Demo result showing real vulnerability
        const sim = SIMULATIONS.find(s => s.id === simId)!
        const checks: CheckResult[] = sim.real_checks.map(c => ({
          label: c.label,
          passed: false,
          actual: 'Не удалось проверить — запустите сканирование',
          fix: c.fix,
        }))
        setResults(r => ({ ...r, [simId]: { status: 'vulnerable', checks, score: 0 } }))
      }
    } finally {
      setRunning(r => ({ ...r, [simId]: false }))
    }
  }

  const runAll = async () => {
    setRunningAll(true)
    for (const sim of SIMULATIONS) {
      await runSim(sim.id)
      await new Promise(r => setTimeout(r, 300))
    }
    setRunningAll(false)
  }

  const exportReport = () => {
    const report = {
      title: 'LinShi Security Testing Report',
      date: new Date().toLocaleString('ru'),
      simulations: SIMULATIONS.map(s => ({
        name: s.name.ru,
        result: results[s.id] || null,
      })),
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `linshi-security-test-${Date.now()}.json`
    a.click()
  }

  const copyCmd = (cmd: string, id: string) => {
    navigator.clipboard.writeText(cmd)
    setCopiedCmd(id)
    setTimeout(() => setCopiedCmd(null), 1500)
  }

  const totalVuln = Object.values(results).filter(r => r.status === 'vulnerable').length
  const totalPartial = Object.values(results).filter(r => r.status === 'partial').length
  const totalProtected = Object.values(results).filter(r => r.status === 'protected').length
  const overallScore = Object.values(results).length > 0
    ? Math.round(Object.values(results).reduce((sum, r) => sum + r.score, 0) / Object.values(results).length)
    : null

  const totalPentestItems = PENTEST_ITEMS.reduce((s, p) => s + p.items.length, 0)

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Target className="w-6 h-6 text-red-400" />
          {lang === 'ru' ? 'Тестирование защиты' : 'Security Testing'}
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          {lang === 'ru'
            ? 'Реальные проверки безопасности системы + чеклист ручного пентеста'
            : 'Real system security checks + manual pentest checklist'}
        </p>
        <div className="mt-2 flex items-center gap-2 text-xs text-yellow-400 bg-yellow-900/20 border border-yellow-800/50 rounded-lg px-3 py-2 w-fit">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
          {lang === 'ru'
            ? 'Проверки читают реальную конфигурацию системы. Никакого вреда не наносится.'
            : 'Checks read real system configuration. No harm is caused.'}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900 border border-gray-800 rounded-xl p-1 w-fit">
        <button onClick={() => setTab('simulation')}
          className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${tab === 'simulation' ? 'bg-red-700 text-white shadow-md' : 'text-gray-400 hover:text-white'}`}>
          {lang === 'ru' ? '⚡ Проверка уязвимостей' : '⚡ Vulnerability Check'}
        </button>
        <button onClick={() => setTab('pentest')}
          className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${tab === 'pentest' ? 'bg-blue-700 text-white shadow-md' : 'text-gray-400 hover:text-white'}`}>
          {lang === 'ru' ? '📋 Pentest Checklist' : '📋 Pentest Checklist'}
        </button>
      </div>

      {/* SIMULATION TAB */}
      {tab === 'simulation' && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex gap-3 flex-wrap">
              {overallScore !== null && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-2 text-center">
                  <div className="text-2xl font-bold" style={{ color: overallScore >= 80 ? '#27ae60' : overallScore >= 60 ? '#f39c12' : '#e74c3c' }}>{overallScore}</div>
                  <div className="text-xs text-gray-400">{lang === 'ru' ? 'Общий балл' : 'Overall Score'}</div>
                </div>
              )}
              {Object.keys(results).length > 0 && (
                <>
                  <div className="flex items-center gap-2 bg-red-900/20 border border-red-800 rounded-lg px-3 py-1.5 text-sm">
                    <XCircle className="w-4 h-4 text-red-400" />
                    <span className="text-red-300 font-medium">{totalVuln}</span>
                    <span className="text-gray-400">{lang === 'ru' ? 'уязвимых' : 'vulnerable'}</span>
                  </div>
                  <div className="flex items-center gap-2 bg-yellow-900/20 border border-yellow-800 rounded-lg px-3 py-1.5 text-sm">
                    <AlertTriangle className="w-4 h-4 text-yellow-400" />
                    <span className="text-yellow-300 font-medium">{totalPartial}</span>
                    <span className="text-gray-400">{lang === 'ru' ? 'частично' : 'partial'}</span>
                  </div>
                  <div className="flex items-center gap-2 bg-green-900/20 border border-green-800 rounded-lg px-3 py-1.5 text-sm">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    <span className="text-green-300 font-medium">{totalProtected}</span>
                    <span className="text-gray-400">{lang === 'ru' ? 'защищённых' : 'protected'}</span>
                  </div>
                </>
              )}
            </div>
            <div className="flex gap-2">
              {Object.keys(results).length > 0 && (
                <button onClick={exportReport}
                  className="flex items-center gap-1.5 text-xs px-3 py-2 bg-gray-800 border border-gray-700 text-gray-300 hover:text-white rounded-lg transition-colors">
                  <Download className="w-3.5 h-3.5" />
                  {lang === 'ru' ? 'Экспорт' : 'Export'}
                </button>
              )}
              <button onClick={runAll} disabled={runningAll}
                className="flex items-center gap-2 bg-gradient-to-r from-red-700 to-red-800 hover:from-red-600 hover:to-red-700 disabled:opacity-60 text-white px-5 py-2.5 rounded-xl text-sm font-medium shadow-lg shadow-red-900/30 transition-all">
                {runningAll ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                {lang === 'ru' ? 'Проверить всё' : 'Check All'}
              </button>
            </div>
          </div>

          {/* Hint */}
          {Object.keys(results).length === 0 && (
            <div className="bg-blue-900/20 border border-blue-800/50 rounded-xl p-4 text-sm text-blue-300 flex items-start gap-2">
              <Shield className="w-4 h-4 mt-0.5 flex-shrink-0" />
              {lang === 'ru'
                ? 'Нажмите "Проверить всё" — система реально проверит каждый параметр безопасности и покажет что уязвимо.'
                : 'Click "Check All" — the system will really check each security parameter and show what is vulnerable.'}
            </div>
          )}

          {/* Simulations */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {SIMULATIONS.map(sim => {
              const result = results[sim.id]
              const isRunning = running[sim.id]
              const isExpanded = expandedSim === sim.id
              const statusColor = result
                ? result.status === 'protected' ? 'border-green-800/70'
                  : result.status === 'partial' ? 'border-yellow-800/70'
                  : 'border-red-800/70'
                : 'border-gray-800'

              return (
                <div key={sim.id} className={`bg-gray-900 border rounded-xl overflow-hidden transition-all ${statusColor}`}>
                  <div className="p-4">
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex items-center gap-3">
                        <span className="text-2xl">{sim.icon}</span>
                        <div>
                          <div className="font-semibold text-white text-sm">{sim.name[lang]}</div>
                          <div className="text-xs text-gray-500 mt-0.5">{sim.description[lang]}</div>
                        </div>
                      </div>
                      {isRunning ? <RefreshCw className="w-5 h-5 text-blue-400 animate-spin flex-shrink-0" />
                        : result?.status === 'protected' ? <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                        : result?.status === 'partial' ? <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0" />
                        : result?.status === 'vulnerable' ? <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
                        : null}
                    </div>

                    {/* Score bar */}
                    {result && (
                      <div className="mb-3">
                        <div className="flex justify-between text-xs mb-1">
                          <span className={result.status === 'protected' ? 'text-green-400' : result.status === 'partial' ? 'text-yellow-400' : 'text-red-400'}>
                            {result.status === 'protected' ? (lang === 'ru' ? '✓ ЗАЩИЩЁН' : '✓ PROTECTED')
                              : result.status === 'partial' ? (lang === 'ru' ? '⚠ ЧАСТИЧНО' : '⚠ PARTIAL')
                              : (lang === 'ru' ? '✗ УЯЗВИМ' : '✗ VULNERABLE')}
                          </span>
                          <span className="text-gray-400">{result.score}%</span>
                        </div>
                        <div className="bg-gray-800 rounded-full h-1.5">
                          <div className="h-1.5 rounded-full transition-all"
                            style={{
                              width: `${result.score}%`,
                              background: result.score >= 80 ? '#27ae60' : result.score >= 50 ? '#f39c12' : '#e74c3c'
                            }} />
                        </div>
                      </div>
                    )}

                    <div className="flex gap-2">
                      <button onClick={() => runSim(sim.id)} disabled={isRunning}
                        className="flex-1 text-xs py-1.5 rounded-lg border transition-colors disabled:opacity-50 border-gray-700 text-gray-400 hover:bg-gray-800 hover:text-white flex items-center justify-center gap-1.5">
                        {isRunning ? <><RefreshCw className="w-3 h-3 animate-spin" />{lang === 'ru' ? 'Проверка...' : 'Checking...'}</>
                          : <><Play className="w-3 h-3" />{lang === 'ru' ? 'Проверить' : 'Check'}</>}
                      </button>
                      {result && (
                        <button onClick={() => setExpandedSim(isExpanded ? null : sim.id)}
                          className="text-xs px-3 py-1.5 rounded-lg border border-gray-700 text-gray-400 hover:bg-gray-800 hover:text-white transition-colors">
                          {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Detailed results */}
                  {isExpanded && result && (
                    <div className="border-t border-gray-800 divide-y divide-gray-800/50">
                      {result.checks.map((c, i) => (
                        <div key={i} className={`px-4 py-3 ${c.passed ? 'bg-green-900/10' : 'bg-red-900/10'}`}>
                          <div className="flex items-center justify-between mb-1">
                            <div className="flex items-center gap-2">
                              {c.passed
                                ? <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                                : <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />}
                              <span className="text-xs text-white">{c.label}</span>
                            </div>
                          </div>
                          {c.actual && <div className="text-xs text-gray-500 ml-5 mb-1">
                            {lang === 'ru' ? 'Значение: ' : 'Value: '}<span className="font-mono text-gray-300">{c.actual}</span>
                          </div>}
                          {!c.passed && c.fix && (
                            <div className="ml-5 mt-1">
                              <div className="text-xs text-blue-400 mb-1 flex items-center gap-1">
                                <Terminal className="w-3 h-3" />
                                {lang === 'ru' ? 'Исправление:' : 'Fix:'}
                              </div>
                              <div className="relative">
                                <pre className="bg-gray-950 rounded p-2 text-xs text-green-300 font-mono overflow-x-auto whitespace-pre-wrap">{c.fix}</pre>
                                <button onClick={() => copyCmd(c.fix!, `${sim.id}-${i}`)}
                                  className="absolute top-1 right-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-400 px-1.5 py-0.5 rounded">
                                  {copiedCmd === `${sim.id}-${i}` ? '✓' : lang === 'ru' ? 'Копировать' : 'Copy'}
                                </button>
                              </div>
                            </div>
                          )}
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

      {/* PENTEST CHECKLIST TAB */}
      {tab === 'pentest' && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-center gap-4">
            <div className="flex-1">
              <div className="flex justify-between text-xs text-gray-400 mb-1.5">
                <span>{lang === 'ru' ? 'Прогресс' : 'Progress'}</span>
                <span>{checkedItems.size} / {totalPentestItems}</span>
              </div>
              <div className="bg-gray-800 rounded-full h-2">
                <div className="bg-blue-500 h-2 rounded-full transition-all"
                  style={{ width: `${(checkedItems.size / totalPentestItems) * 100}%` }} />
              </div>
            </div>
            <button onClick={() => setCheckedItems(new Set())}
              className="text-xs text-gray-500 hover:text-gray-300 px-3 py-1.5 border border-gray-700 rounded-lg">
              {lang === 'ru' ? 'Сбросить' : 'Reset'}
            </button>
          </div>

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
                      <span className="text-xs text-gray-500">{phaseChecked}/{phase.items.length}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-gray-800 rounded-full h-1.5">
                        <div className="h-1.5 rounded-full bg-blue-500 transition-all"
                          style={{ width: `${(phaseChecked / phase.items.length) * 100}%` }} />
                      </div>
                      {isOpen ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
                    </div>
                  </button>

                  {isOpen && (
                    <div className="divide-y divide-gray-800/50">
                      {phase.items.map(item => (
                        <div key={item.id} className={`p-4 ${checkedItems.has(item.id) ? 'bg-green-900/10' : ''}`}>
                          <div className="flex items-start gap-3">
                            <input type="checkbox" checked={checkedItems.has(item.id)}
                              onChange={() => setCheckedItems(prev => { const n = new Set(prev); n.has(item.id) ? n.delete(item.id) : n.add(item.id); return n })}
                              className="mt-0.5 w-4 h-4 accent-green-500 cursor-pointer flex-shrink-0" />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1 flex-wrap">
                                <span className={`font-medium text-sm ${checkedItems.has(item.id) ? 'text-gray-500 line-through' : 'text-white'}`}>
                                  {item.name[lang]}
                                </span>
                                <span className={`text-xs px-1.5 py-0.5 rounded border ${RISK_STYLE[item.risk]}`}>{item.risk}</span>
                              </div>
                              <p className="text-xs text-gray-400 mb-2">{item.desc[lang]}</p>
                              <div className="relative">
                                <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs text-green-300 font-mono overflow-x-auto whitespace-pre">
                                  {item.cmd}
                                </pre>
                                <button onClick={() => copyCmd(item.cmd, item.id)}
                                  className="absolute top-2 right-2 text-xs bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white px-2 py-0.5 rounded transition-colors">
                                  {copiedCmd === item.id ? '✓' : lang === 'ru' ? 'Копировать' : 'Copy'}
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
