import { useState, useEffect, useRef } from 'react'
import { Monitor, Apple, Server, Play, RefreshCw, ChevronDown, ChevronUp,
         CheckCircle, XCircle, AlertTriangle, Info, Shield, Wifi, User,
         HardDrive, Settings, Terminal, Eye, EyeOff, Download } from 'lucide-react'
import axios from 'axios'
import { useLang } from '../i18n'

const api = axios.create({ baseURL: '/api' })
api.interceptors.request.use(c => {
  const t = localStorage.getItem('access_token')
  if (t) c.headers.Authorization = `Bearer ${t}`
  return c
})

// ── Types ──────────────────────────────────────────────────────────────────
type OsType = 'linux' | 'windows' | 'macos'
type ScanType = 'local' | 'remote'
type FindingStatus = 'pass' | 'fail' | 'warning' | 'info'
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

interface Finding {
  check_id: string
  name: string
  status: FindingStatus
  severity: Severity
  description: string
  current_value: string
  expected_value: string
  recommendation: string
  fix_cmd?: string
  cis_control?: string
  nist_control?: string
  category: string
}

interface ScanResult {
  scan_id: string
  status: string
  progress: number
  os_type: OsType
  host: string
  started_at: string
  findings?: Finding[]
  score?: number
  stats?: any
  error?: string
}

// ── Constants ──────────────────────────────────────────────────────────────

const OS_OPTIONS = [
  {
    id: 'linux' as OsType,
    label: 'Linux',
    icon: '🐧',
    color: 'from-orange-900/40 to-orange-800/20 border-orange-700',
    activeColor: 'from-orange-600 to-orange-700 border-orange-500',
    desc: { ru: 'Ubuntu, Debian, CentOS, RHEL, Kali', en: 'Ubuntu, Debian, CentOS, RHEL, Kali' },
    checks: { ru: '50+ проверок', en: '50+ checks' },
  },
  {
    id: 'windows' as OsType,
    label: 'Windows',
    icon: '🪟',
    color: 'from-blue-900/40 to-blue-800/20 border-blue-700',
    activeColor: 'from-blue-600 to-blue-700 border-blue-500',
    desc: { ru: 'Windows Server 2016/2019/2022, Windows 10/11', en: 'Windows Server 2016/2019/2022, Windows 10/11' },
    checks: { ru: '30+ проверок via PowerShell', en: '30+ checks via PowerShell' },
  },
  {
    id: 'macos' as OsType,
    label: 'macOS',
    icon: '🍎',
    color: 'from-gray-700/40 to-gray-600/20 border-gray-600',
    activeColor: 'from-gray-500 to-gray-600 border-gray-400',
    desc: { ru: 'macOS 12 Monterey, 13 Ventura, 14 Sonoma', en: 'macOS 12 Monterey, 13 Ventura, 14 Sonoma' },
    checks: { ru: '30+ проверок', en: '30+ checks' },
  },
]

const CATEGORY_LABELS: Record<string, { ru: string; en: string; icon: string }> = {
  ssh:        { ru: 'SSH',              en: 'SSH',              icon: '🔐' },
  password:   { ru: 'Пароли',          en: 'Passwords',        icon: '🔑' },
  network:    { ru: 'Сеть',            en: 'Network',          icon: '🌐' },
  system:     { ru: 'Система',         en: 'System',           icon: '⚙️' },
  filesystem: { ru: 'Файловая система',en: 'Filesystem',       icon: '📁' },
  users:      { ru: 'Пользователи',    en: 'Users',            icon: '👥' },
  services:   { ru: 'Сервисы',         en: 'Services',         icon: '🔧' },
  kernel:     { ru: 'Ядро',           en: 'Kernel',           icon: '⚡' },
  logging:    { ru: 'Логирование',     en: 'Logging',          icon: '📋' },
  security:   { ru: 'Безопасность',    en: 'Security',         icon: '🛡️' },
  policy:     { ru: 'Политики',        en: 'Policies',         icon: '📜' },
  general:    { ru: 'Общее',          en: 'General',          icon: '🔍' },
}

const STATUS_STYLE: Record<FindingStatus, { icon: JSX.Element; bg: string; text: string; border: string }> = {
  pass:    { icon: <CheckCircle className="w-4 h-4 text-green-400" />,    bg: 'bg-green-900/20',  text: 'text-green-400',  border: 'border-green-800' },
  fail:    { icon: <XCircle className="w-4 h-4 text-red-400" />,          bg: 'bg-red-900/20',    text: 'text-red-400',    border: 'border-red-800' },
  warning: { icon: <AlertTriangle className="w-4 h-4 text-yellow-400" />, bg: 'bg-yellow-900/20', text: 'text-yellow-400', border: 'border-yellow-800' },
  info:    { icon: <Info className="w-4 h-4 text-blue-400" />,            bg: 'bg-blue-900/20',   text: 'text-blue-400',   border: 'border-blue-800' },
}

const SEV_COLOR: Record<Severity, string> = {
  critical: 'text-red-400 bg-red-900/30 border-red-800',
  high:     'text-orange-400 bg-orange-900/30 border-orange-800',
  medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-800',
  low:      'text-blue-400 bg-blue-900/30 border-blue-800',
  info:     'text-gray-400 bg-gray-800 border-gray-700',
}

const scoreColor = (s: number) => s >= 80 ? '#27ae60' : s >= 60 ? '#f39c12' : '#e74c3c'

// ── Component ──────────────────────────────────────────────────────────────

export default function OSScan() {
  const { lang } = useLang()
  const [osType, setOsType] = useState<OsType>('linux')
  const [scanType, setScanType] = useState<ScanType>('local')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('22')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [sshKey, setSshKey] = useState('')
  const [authMethod, setAuthMethod] = useState<'password' | 'key'>('password')
  const [scanning, setScanning] = useState(false)
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set())
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current) }, [])

  // When OS changes, update default port
  useEffect(() => {
    if (osType === 'windows') setPort('22')
    else setPort('22')
  }, [osType])

  const startScan = async () => {
    setScanning(true)
    setScan(null)
    try {
      const payload: any = { os_type: osType, scan_type: scanType }
      if (scanType === 'remote') {
        payload.host = host
        payload.port = parseInt(port) || 22
        payload.username = username
        if (authMethod === 'password') payload.password = password
        else payload.ssh_key = sshKey
      }
      const res = await api.post('/os-scan/start', payload)
      const scanId = res.data.scan_id
      setScan({ scan_id: scanId, status: 'starting', progress: 0, os_type: osType, host: host || 'localhost', started_at: new Date().toISOString() })

      pollRef.current = setInterval(async () => {
        try {
          const r = await api.get(`/os-scan/${scanId}`)
          setScan(r.data)
          if (r.data.status === 'completed' || r.data.status === 'failed') {
            if (pollRef.current) clearInterval(pollRef.current)
            setScanning(false)
            if (r.data.findings) {
              const cats = new Set(r.data.findings.map((f: Finding) => f.category))
              setExpandedCategories(cats)
            }
          }
        } catch {}
      }, 1500)
    } catch (e: any) {
      setScan({ scan_id: '', status: 'failed', progress: 0, os_type: osType, host: host || 'localhost', started_at: new Date().toISOString(), error: e?.response?.data?.detail || String(e) })
      setScanning(false)
    }
  }

  const toggleCategory = (cat: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev)
      next.has(cat) ? next.delete(cat) : next.add(cat)
      return next
    })
  }

  const toggleFinding = (id: string) => {
    setExpandedFindings(prev => {
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

  const exportReport = () => {
    if (!scan?.findings) return
    const report = {
      title: `LinShi Security Scan Report — ${scan.os_type.toUpperCase()}`,
      host: scan.host,
      date: new Date().toLocaleString('ru'),
      score: scan.score,
      stats: scan.stats,
      findings: scan.findings,
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `linshi-scan-${scan.os_type}-${Date.now()}.json`
    a.click()
  }

  // Group findings by category
  const grouped = scan?.findings ? scan.findings.reduce((acc: Record<string, Finding[]>, f) => {
    if (!acc[f.category]) acc[f.category] = []
    acc[f.category].push(f)
    return acc
  }, {}) : {}

  // Filter findings
  const filteredGrouped = Object.fromEntries(
    Object.entries(grouped).map(([cat, findings]) => [
      cat,
      findings.filter(f => {
        const matchStatus = filterStatus === 'all' || f.status === filterStatus
        const matchSev = filterSeverity === 'all' || f.severity === filterSeverity
        return matchStatus && matchSev
      })
    ]).filter(([, findings]) => findings.length > 0)
  )

  const activeOs = OS_OPTIONS.find(o => o.id === osType)!

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Monitor className="w-6 h-6 text-blue-400" />
          {lang === 'ru' ? 'Сканер безопасности ОС' : 'OS Security Scanner'}
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          {lang === 'ru'
            ? 'Полный аудит безопасности Linux, Windows и macOS систем — локально или по SSH'
            : 'Full security audit for Linux, Windows and macOS systems — local or via SSH'}
        </p>
      </div>

      {/* OS Selection */}
      <div className="grid grid-cols-3 gap-3">
        {OS_OPTIONS.map(os => (
          <button key={os.id} onClick={() => setOsType(os.id)}
            className={`bg-gradient-to-br border rounded-xl p-4 text-left transition-all ${
              osType === os.id ? os.activeColor + ' shadow-lg ring-2 ring-white/10' : os.color + ' hover:brightness-110'
            }`}>
            <div className="flex items-center gap-3 mb-2">
              <span className="text-3xl">{os.icon}</span>
              <span className="font-bold text-white text-lg">{os.label}</span>
              {osType === os.id && <CheckCircle className="w-4 h-4 text-white ml-auto" />}
            </div>
            <div className="text-xs text-gray-300">{os.desc[lang]}</div>
            <div className="text-xs text-white/60 mt-1">✓ {os.checks[lang]}</div>
          </button>
        ))}
      </div>

      {/* Scan Config */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
        <h2 className="font-semibold text-white">
          {lang === 'ru' ? 'Настройки сканирования' : 'Scan Configuration'}
        </h2>

        {/* Local / Remote tabs */}
        <div className="flex gap-1 bg-gray-800 rounded-lg p-1 w-fit">
          <button onClick={() => setScanType('local')}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-all ${scanType === 'local' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}>
            {lang === 'ru' ? '💻 Локальный хост' : '💻 Local Host'}
          </button>
          <button onClick={() => setScanType('remote')}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-all ${scanType === 'remote' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}>
            {lang === 'ru' ? '🌐 Удалённый хост (SSH)' : '🌐 Remote Host (SSH)'}
          </button>
        </div>

        {/* Remote host fields */}
        {scanType === 'remote' && (
          <div className="space-y-3 pt-1">
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="block text-xs text-gray-400 mb-1">
                  {lang === 'ru' ? 'IP адрес / Hostname' : 'IP Address / Hostname'}
                </label>
                <input value={host} onChange={e => setHost(e.target.value)}
                  placeholder="192.168.1.100"
                  className="w-full bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg text-sm focus:outline-none focus:border-blue-500" />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Port</label>
                <input value={port} onChange={e => setPort(e.target.value)}
                  placeholder="22"
                  className="w-full bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg text-sm focus:outline-none focus:border-blue-500" />
              </div>
            </div>

            <div>
              <label className="block text-xs text-gray-400 mb-1">
                {lang === 'ru' ? 'Имя пользователя' : 'Username'}
              </label>
              <input value={username} onChange={e => setUsername(e.target.value)}
                placeholder="root"
                className="w-full bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg text-sm focus:outline-none focus:border-blue-500" />
            </div>

            {/* Auth method */}
            <div>
              <label className="block text-xs text-gray-400 mb-2">
                {lang === 'ru' ? 'Метод аутентификации' : 'Authentication Method'}
              </label>
              <div className="flex gap-2 mb-2">
                {(['password', 'key'] as const).map(m => (
                  <button key={m} onClick={() => setAuthMethod(m)}
                    className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${authMethod === m ? 'bg-blue-600 border-blue-500 text-white' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white'}`}>
                    {m === 'password' ? (lang === 'ru' ? '🔑 Пароль' : '🔑 Password') : (lang === 'ru' ? '🗝️ SSH Ключ' : '🗝️ SSH Key')}
                  </button>
                ))}
              </div>

              {authMethod === 'password' ? (
                <div className="relative">
                  <input type={showPw ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-gray-800 border border-gray-700 text-white px-3 py-2 pr-10 rounded-lg text-sm focus:outline-none focus:border-blue-500" />
                  <button onClick={() => setShowPw(!showPw)} className="absolute right-3 top-2.5 text-gray-400 hover:text-white">
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              ) : (
                <textarea value={sshKey} onChange={e => setSshKey(e.target.value)}
                  placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                  rows={4}
                  className="w-full bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg text-xs font-mono focus:outline-none focus:border-blue-500 resize-none" />
              )}
            </div>
          </div>
        )}

        {/* Info for local scan */}
        {scanType === 'local' && (
          <div className="bg-blue-900/20 border border-blue-800/50 rounded-lg p-3 text-xs text-blue-300 flex items-start gap-2">
            <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
            {lang === 'ru'
              ? `Сканирование текущего сервера (${osType === 'linux' ? 'Linux' : osType === 'windows' ? 'Windows' : 'macOS'}) на котором запущен LinShi.`
              : `Scanning the current server (${osType === 'linux' ? 'Linux' : osType === 'windows' ? 'Windows' : 'macOS'}) where LinShi is running.`}
          </div>
        )}

        {/* Start button */}
        <button onClick={startScan} disabled={scanning || (scanType === 'remote' && !host)}
          className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 disabled:opacity-50 text-white py-3 rounded-xl font-medium transition-all shadow-lg shadow-blue-900/30">
          {scanning ? <RefreshCw className="w-5 h-5 animate-spin" /> : <Play className="w-5 h-5" />}
          {scanning
            ? (lang === 'ru' ? 'Сканирование...' : 'Scanning...')
            : `${lang === 'ru' ? 'Запустить сканирование' : 'Start Scan'} ${activeOs.icon} ${activeOs.label}`}
        </button>
      </div>

      {/* Progress bar */}
      {scan && scan.status !== 'completed' && scan.status !== 'failed' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <div className="flex justify-between text-sm mb-2">
            <span className="text-white">{lang === 'ru' ? 'Сканирование...' : 'Scanning...'} {activeOs.icon} {scan.host}</span>
            <span className="text-blue-400">{scan.progress}%</span>
          </div>
          <div className="bg-gray-800 rounded-full h-2">
            <div className="bg-blue-500 h-2 rounded-full transition-all duration-500" style={{ width: `${scan.progress}%` }} />
          </div>
          <div className="text-xs text-gray-500 mt-1">
            {lang === 'ru' ? 'Выполняются проверки безопасности...' : 'Running security checks...'}
          </div>
        </div>
      )}

      {/* Error */}
      {scan?.status === 'failed' && (
        <div className="bg-red-900/20 border border-red-800 rounded-xl p-4 text-red-300 text-sm">
          <div className="font-medium mb-1">{lang === 'ru' ? 'Ошибка сканирования' : 'Scan Error'}</div>
          <div className="font-mono text-xs">{scan.error}</div>
        </div>
      )}

      {/* Results */}
      {scan?.status === 'completed' && scan.findings && scan.stats && (
        <div className="space-y-4">
          {/* Score + Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {/* Score card */}
            <div className="col-span-2 md:col-span-1 bg-gray-900 border border-gray-800 rounded-xl p-5 flex flex-col items-center justify-center">
              <div className="text-5xl font-bold mb-1" style={{ color: scoreColor(scan.score!) }}>{scan.score}</div>
              <div className="text-xs text-gray-400">{lang === 'ru' ? 'Индекс безопасности' : 'Security Score'}</div>
              <div className="text-xs font-medium mt-1" style={{ color: scoreColor(scan.score!) }}>
                {scan.score! >= 80 ? (lang === 'ru' ? 'Хорошо' : 'Good')
                  : scan.score! >= 60 ? (lang === 'ru' ? 'Средне' : 'Medium')
                  : (lang === 'ru' ? 'Критично' : 'Critical')}
              </div>
            </div>

            {[
              { label: lang === 'ru' ? 'Пройдено' : 'Passed', val: scan.stats.passed, color: 'text-green-400' },
              { label: lang === 'ru' ? 'Ошибок' : 'Failed', val: scan.stats.failed, color: 'text-red-400' },
              { label: lang === 'ru' ? 'Предупреждений' : 'Warnings', val: scan.stats.warnings, color: 'text-yellow-400' },
            ].map(s => (
              <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
                <div className={`text-3xl font-bold ${s.color}`}>{s.val}</div>
                <div className="text-xs text-gray-400 mt-1">{s.label}</div>
              </div>
            ))}
          </div>

          {/* Severity breakdown */}
          <div className="grid grid-cols-4 gap-2">
            {[
              { key: 'critical', label: lang === 'ru' ? 'Критических' : 'Critical', color: 'border-red-800 text-red-400' },
              { key: 'high',     label: lang === 'ru' ? 'Высоких' : 'High',         color: 'border-orange-800 text-orange-400' },
              { key: 'medium',   label: lang === 'ru' ? 'Средних' : 'Medium',       color: 'border-yellow-800 text-yellow-400' },
              { key: 'low',      label: lang === 'ru' ? 'Низких' : 'Low',           color: 'border-blue-800 text-blue-400' },
            ].map(s => (
              <div key={s.key} className={`bg-gray-900 border rounded-xl p-3 text-center ${s.color}`}>
                <div className="text-2xl font-bold">{scan.stats[s.key]}</div>
                <div className="text-xs opacity-70">{s.label}</div>
              </div>
            ))}
          </div>

          {/* Actions row */}
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex gap-2 flex-wrap">
              {/* Status filter */}
              {['all', 'fail', 'warning', 'pass', 'info'].map(s => (
                <button key={s} onClick={() => setFilterStatus(s)}
                  className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${filterStatus === s ? 'bg-blue-600 border-blue-500 text-white' : 'bg-gray-900 border-gray-700 text-gray-400 hover:text-white'}`}>
                  {s === 'all' ? (lang === 'ru' ? 'Все' : 'All')
                    : s === 'fail' ? (lang === 'ru' ? '❌ Ошибки' : '❌ Failed')
                    : s === 'warning' ? (lang === 'ru' ? '⚠️ Предупреждения' : '⚠️ Warnings')
                    : s === 'pass' ? (lang === 'ru' ? '✅ Пройдено' : '✅ Passed')
                    : (lang === 'ru' ? 'ℹ️ Инфо' : 'ℹ️ Info')}
                </button>
              ))}
            </div>
            <button onClick={exportReport}
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-gray-800 border border-gray-700 text-gray-300 hover:text-white rounded-lg transition-colors">
              <Download className="w-3.5 h-3.5" />
              {lang === 'ru' ? 'Экспорт JSON' : 'Export JSON'}
            </button>
          </div>

          {/* Findings by category */}
          <div className="space-y-2">
            {Object.entries(filteredGrouped).map(([cat, findings]) => {
              const catInfo = CATEGORY_LABELS[cat] || { ru: cat, en: cat, icon: '🔍' }
              const failed = findings.filter(f => f.status === 'fail').length
              const warnings = findings.filter(f => f.status === 'warning').length
              const passed = findings.filter(f => f.status === 'pass').length
              const isOpen = expandedCategories.has(cat)

              return (
                <div key={cat} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                  <button className="w-full p-4 text-left flex items-center justify-between hover:bg-gray-800/40 transition-colors"
                    onClick={() => toggleCategory(cat)}>
                    <div className="flex items-center gap-3">
                      <span className="text-xl">{catInfo.icon}</span>
                      <span className="font-medium text-white">{catInfo[lang]}</span>
                      <span className="text-xs text-gray-500">{findings.length} {lang === 'ru' ? 'проверок' : 'checks'}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {failed > 0 && <span className="text-xs bg-red-900/40 text-red-300 border border-red-800 px-2 py-0.5 rounded">❌ {failed}</span>}
                      {warnings > 0 && <span className="text-xs bg-yellow-900/40 text-yellow-300 border border-yellow-800 px-2 py-0.5 rounded">⚠️ {warnings}</span>}
                      {passed > 0 && <span className="text-xs bg-green-900/40 text-green-300 border border-green-800 px-2 py-0.5 rounded">✅ {passed}</span>}
                      {isOpen ? <ChevronUp className="w-4 h-4 text-gray-400 ml-1" /> : <ChevronDown className="w-4 h-4 text-gray-400 ml-1" />}
                    </div>
                  </button>

                  {isOpen && (
                    <div className="divide-y divide-gray-800/60">
                      {findings.map(f => {
                        const st = STATUS_STYLE[f.status]
                        const isExpanded = expandedFindings.has(f.check_id)
                        return (
                          <div key={f.check_id} className={`${st.bg} border-l-4 ${st.border}`}>
                            <button className="w-full px-4 py-3 text-left flex items-center justify-between"
                              onClick={() => toggleFinding(f.check_id)}>
                              <div className="flex items-center gap-3 min-w-0">
                                {st.icon}
                                <span className="text-sm text-white truncate">{f.name}</span>
                                <span className={`text-xs px-1.5 py-0.5 rounded border flex-shrink-0 ${SEV_COLOR[f.severity]}`}>
                                  {f.severity}
                                </span>
                              </div>
                              {isExpanded ? <ChevronUp className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" /> : <ChevronDown className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />}
                            </button>

                            {isExpanded && (
                              <div className="px-4 pb-4 space-y-3 border-t border-gray-800/50 pt-3">
                                <p className="text-sm text-gray-300">{f.description}</p>

                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                                  <div className="bg-gray-800/50 rounded-lg p-3">
                                    <div className="text-gray-500 mb-1">{lang === 'ru' ? 'Текущее значение' : 'Current Value'}</div>
                                    <div className="text-white font-mono break-all">{f.current_value}</div>
                                  </div>
                                  <div className="bg-gray-800/50 rounded-lg p-3">
                                    <div className="text-gray-500 mb-1">{lang === 'ru' ? 'Ожидаемое значение' : 'Expected Value'}</div>
                                    <div className="text-green-300 font-mono break-all">{f.expected_value}</div>
                                  </div>
                                </div>

                                <div className="bg-gray-800/50 rounded-lg p-3">
                                  <div className="text-xs text-gray-500 mb-1">💡 {lang === 'ru' ? 'Рекомендация' : 'Recommendation'}</div>
                                  <div className="text-sm text-gray-200">{f.recommendation}</div>
                                </div>

                                {f.fix_cmd && (
                                  <div>
                                    <div className="text-xs text-blue-400 mb-1 flex items-center gap-1">
                                      <Terminal className="w-3 h-3" />
                                      {lang === 'ru' ? 'Команда исправления' : 'Fix Command'}
                                    </div>
                                    <div className="relative">
                                      <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs text-green-300 font-mono overflow-x-auto whitespace-pre">
                                        {f.fix_cmd}
                                      </pre>
                                      <button onClick={() => copyCmd(f.fix_cmd!, f.check_id)}
                                        className="absolute top-2 right-2 text-xs bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white px-2 py-0.5 rounded transition-colors">
                                        {copiedCmd === f.check_id ? '✓' : lang === 'ru' ? 'Копировать' : 'Copy'}
                                      </button>
                                    </div>
                                  </div>
                                )}

                                {(f.cis_control || f.nist_control) && (
                                  <div className="flex gap-2 flex-wrap">
                                    {f.cis_control && <span className="text-xs bg-blue-900/30 text-blue-300 border border-blue-800/50 px-2 py-1 rounded">{f.cis_control}</span>}
                                    {f.nist_control && <span className="text-xs bg-purple-900/30 text-purple-300 border border-purple-800/50 px-2 py-1 rounded">{f.nist_control}</span>}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )
                      })}
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
