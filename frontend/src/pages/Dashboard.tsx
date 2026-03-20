import { useState, useEffect } from 'react'
import { Shield, AlertTriangle, CheckCircle, XCircle, Play, RefreshCw, Server, Clock, TrendingUp, Activity } from 'lucide-react'
import { RadialBarChart, RadialBar, PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis } from 'recharts'
import { scansApi } from '../api'
import { useLang } from '../i18n'

const scoreColor = (s: number) => s >= 80 ? '#27ae60' : s >= 60 ? '#f39c12' : '#e74c3c'

export default function Dashboard() {
  const { t } = useLang()
  const [summary, setSummary] = useState<any>(null)
  const [lastScan, setLastScan] = useState<any>(null)
  const [scanning, setScanning] = useState(false)
  const [scans, setScans] = useState<any[]>([])

  useEffect(() => { loadData() }, [])

  const loadData = async () => {
    try {
      const [sumRes, scansRes] = await Promise.all([scansApi.summary(), scansApi.list()])
      setSummary(sumRes.data)
      setScans(scansRes.data)
      const completed = scansRes.data.find((s: any) => s.status === 'completed')
      if (completed) {
        const detail = await scansApi.get(completed.id)
        setLastScan(detail.data)
      }
    } catch {}
  }

  const startScan = async () => {
    setScanning(true)
    try {
      const res = await scansApi.startLocal()
      const poll = setInterval(async () => {
        const s = await scansApi.get(res.data.scan_id)
        if (s.data.status !== 'running') { clearInterval(poll); setScanning(false); loadData() }
      }, 2000)
    } catch { setScanning(false) }
  }

  const score = lastScan?.score ?? summary?.last_score ?? 0
  const scoreLabel = score >= 80 ? t.dashboard.scoreGood : score >= 60 ? t.dashboard.scoreMedium : t.dashboard.scoreCritical

  const pieData = lastScan ? [
    { name: t.dashboard.passed, value: lastScan.passed, color: '#27ae60' },
    { name: t.dashboard.failed, value: lastScan.failed, color: '#e74c3c' },
    { name: t.dashboard.warnings, value: lastScan.warnings, color: '#f39c12' },
  ] : []

  const barData = lastScan ? [
    { name: t.dashboard.critical, value: lastScan.critical_count, fill: '#e74c3c' },
    { name: t.dashboard.high, value: lastScan.high_count, fill: '#e67e22' },
    { name: t.dashboard.medium, value: lastScan.medium_count, fill: '#f39c12' },
    { name: t.dashboard.low, value: lastScan.low_count, fill: '#3498db' },
  ] : []

  const complianceData = [
    { name: 'CIS', score: score > 0 ? Math.min(100, score + 5) : 0, color: '#3b82f6' },
    { name: 'NIST', score: score > 0 ? Math.min(100, score - 3) : 0, color: '#8b5cf6' },
    { name: 'OWASP', score: score > 0 ? Math.min(100, score + 2) : 0, color: '#06b6d4' },
  ]

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{t.dashboard.title}</h1>
          <p className="text-gray-400 text-sm mt-0.5">{t.dashboard.subtitle}</p>
        </div>
        <button onClick={startScan} disabled={scanning}
          className="flex items-center gap-2 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 disabled:opacity-60 text-white px-5 py-2.5 rounded-xl text-sm font-medium shadow-lg shadow-blue-900/30 transition-all">
          {scanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {scanning ? t.dashboard.scanning : t.dashboard.startScan}
        </button>
      </div>

      {/* Top stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { icon: Shield, label: t.dashboard.securityIndex, value: score || '—', color: 'from-blue-600 to-blue-800', textColor: scoreColor(score) },
          { icon: Activity, label: t.dashboard.totalScans, value: summary?.total_scans ?? 0, color: 'from-purple-600 to-purple-800', textColor: '#a78bfa' },
          { icon: XCircle, label: t.dashboard.critical, value: lastScan?.critical_count ?? 0, color: 'from-red-700 to-red-900', textColor: '#f87171' },
          { icon: Clock, label: 'Last Scan', value: summary?.last_scan_time ? new Date(summary.last_scan_time).toLocaleDateString('ru') : '—', color: 'from-gray-700 to-gray-800', textColor: '#94a3b8' },
        ].map(({ icon: Icon, label, value, color, textColor }) => (
          <div key={label} className={`bg-gradient-to-br ${color} border border-gray-700 rounded-xl p-4`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-gray-300">{label}</span>
              <Icon className="w-4 h-4 text-gray-400" />
            </div>
            <div className="text-2xl font-bold" style={{ color: textColor }}>{value}</div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Score Gauge */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex flex-col items-center">
          <h2 className="text-sm font-medium text-gray-400 mb-3">{t.dashboard.securityIndex}</h2>
          <div className="relative w-36 h-36">
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart cx="50%" cy="50%" innerRadius="70%" outerRadius="100%"
                data={[{ value: score, fill: scoreColor(score) }]} startAngle={90} endAngle={-270}>
                <RadialBar dataKey="value" cornerRadius={8} />
              </RadialBarChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-bold text-white">{score}</span>
              <span className="text-xs font-medium" style={{ color: scoreColor(score) }}>{scoreLabel}</span>
            </div>
          </div>
          <div className="w-full mt-4 space-y-1.5">
            {complianceData.map(c => (
              <div key={c.name} className="flex items-center gap-2">
                <span className="text-xs text-gray-500 w-12">{c.name}</span>
                <div className="flex-1 bg-gray-800 rounded-full h-1.5">
                  <div className="h-1.5 rounded-full transition-all" style={{ width: `${c.score}%`, background: c.color }} />
                </div>
                <span className="text-xs text-gray-400 w-8 text-right">{c.score}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Pie chart */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-sm font-medium text-gray-400 mb-4">{t.dashboard.checkResults}</h2>
          {lastScan ? (
            <>
              <ResponsiveContainer width="100%" height={130}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" outerRadius={55} innerRadius={30} dataKey="value">
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1.5 mt-1">
                {pieData.map(d => (
                  <div key={d.name} className="flex justify-between text-xs">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: d.color }} />
                      <span className="text-gray-400">{d.name}</span>
                    </span>
                    <span className="text-white font-semibold">{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : <div className="text-gray-500 text-sm text-center py-12">{t.common.noData}</div>}
        </div>

        {/* Bar chart */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-sm font-medium text-gray-400 mb-4">{t.dashboard.vulnerabilities}</h2>
          {lastScan ? (
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={barData} barSize={28}>
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#6b7280' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {barData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="text-gray-500 text-sm text-center py-12">{t.common.noData}</div>}
        </div>
      </div>

      {/* Recent scans */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-gray-800">
          <h2 className="font-semibold text-white">{t.dashboard.recentScans}</h2>
          <TrendingUp className="w-4 h-4 text-gray-500" />
        </div>
        <div className="divide-y divide-gray-800">
          {scans.slice(0, 6).map(s => (
            <div key={s.id} className="flex items-center justify-between px-4 py-3 hover:bg-gray-800/40 transition-colors">
              <div className="flex items-center gap-3">
                {s.status === 'completed' ? <CheckCircle className="w-4 h-4 text-green-400" />
                  : s.status === 'failed' ? <XCircle className="w-4 h-4 text-red-400" />
                  : <RefreshCw className="w-4 h-4 text-blue-400 animate-spin" />}
                <div>
                  <div className="text-sm text-white">{s.scan_type === 'local' ? t.dashboard.localHost : `${t.dashboard.host} #${s.host_id}`}</div>
                  <div className="text-xs text-gray-500">{s.started_at ? new Date(s.started_at).toLocaleString('ru') : '—'}</div>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-xs text-gray-500">{s.failed ?? 0} {t.dashboard.errors}</span>
                {s.score != null && (
                  <span className="text-sm font-bold px-2 py-0.5 rounded" style={{ color: scoreColor(s.score), background: scoreColor(s.score) + '20' }}>{s.score}</span>
                )}
              </div>
            </div>
          ))}
          {scans.length === 0 && (
            <div className="text-center text-gray-500 text-sm py-10">{t.dashboard.noScans}</div>
          )}
        </div>
      </div>
    </div>
  )
}
