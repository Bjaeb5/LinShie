import { useState, useEffect } from 'react'
import { Play, ChevronDown, ChevronUp, RefreshCw, CheckCircle, XCircle, AlertTriangle, Filter } from 'lucide-react'
import { scansApi } from '../api'

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/20 border-red-800',
  high: 'text-orange-400 bg-orange-900/20 border-orange-800',
  medium: 'text-yellow-400 bg-yellow-900/20 border-yellow-800',
  low: 'text-blue-400 bg-blue-900/20 border-blue-800',
}
const STATUS_ICON: Record<string, React.ReactNode> = {
  pass: <CheckCircle className="w-4 h-4 text-green-400" />,
  fail: <XCircle className="w-4 h-4 text-red-400" />,
  warning: <AlertTriangle className="w-4 h-4 text-yellow-400" />,
}

export default function Scans() {
  const [scans, setScans] = useState<any[]>([])
  const [selected, setSelected] = useState<any>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [filter, setFilter] = useState<string>('all')
  const [scanning, setScanning] = useState(false)

  useEffect(() => { loadScans() }, [])

  const loadScans = async () => {
    const res = await scansApi.list()
    setScans(res.data)
    if (res.data.length > 0 && res.data[0].status === 'completed') {
      const detail = await scansApi.get(res.data[0].id)
      setSelected(detail.data)
    }
  }

  const startScan = async () => {
    setScanning(true)
    const res = await scansApi.startLocal()
    const poll = setInterval(async () => {
      const s = await scansApi.get(res.data.scan_id)
      if (s.data.status !== 'running') {
        clearInterval(poll); setScanning(false)
        setSelected(s.data); loadScans()
      }
    }, 2000)
  }

  const selectScan = async (scan: any) => {
    if (scan.status !== 'completed') return
    const detail = await scansApi.get(scan.id)
    setSelected(detail.data)
  }

  const findings = selected?.findings?.filter((f: any) =>
    filter === 'all' || f.status === filter || f.severity === filter
  ) ?? []

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Сканирования</h1>
        <button onClick={startScan} disabled={scanning}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white px-4 py-2 rounded-lg text-sm font-medium">
          {scanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {scanning ? 'Сканирование...' : 'Новое сканирование'}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan list */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="p-3 border-b border-gray-800 text-sm font-medium text-gray-400">История</div>
          <div className="divide-y divide-gray-800 max-h-96 overflow-y-auto">
            {scans.map(s => (
              <button key={s.id} onClick={() => selectScan(s)}
                className={`w-full text-left px-4 py-3 hover:bg-gray-800 transition-colors ${selected?.id === s.id ? 'bg-gray-800' : ''}`}>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-white">#{s.id} {s.scan_type === 'local' ? 'Локальный' : 'Удалённый'}</span>
                  {s.status === 'running' ? <RefreshCw className="w-3.5 h-3.5 text-blue-400 animate-spin" />
                    : s.score != null ? <span className={`text-sm font-bold ${s.score >= 80 ? 'text-green-400' : s.score >= 60 ? 'text-yellow-400' : 'text-red-400'}`}>{s.score}</span>
                    : <span className="text-xs text-red-400">Ошибка</span>}
                </div>
                <div className="text-xs text-gray-500 mt-0.5">{s.started_at ? new Date(s.started_at).toLocaleString('ru') : ''}</div>
              </button>
            ))}
            {scans.length === 0 && <div className="text-center text-gray-500 text-sm py-8">Нет данных</div>}
          </div>
        </div>

        {/* Findings */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="p-3 border-b border-gray-800 flex items-center gap-2 flex-wrap">
            <Filter className="w-4 h-4 text-gray-500" />
            {['all', 'fail', 'warning', 'critical', 'high', 'medium', 'low'].map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${filter === f ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-white'}`}>
                {f === 'all' ? 'Все' : f}
              </button>
            ))}
          </div>
          <div className="divide-y divide-gray-800 max-h-[500px] overflow-y-auto">
            {findings.map((f: any) => (
              <div key={f.check_id} className="p-4">
                <button className="w-full text-left" onClick={() => setExpanded(expanded === f.check_id ? null : f.check_id)}>
                  <div className="flex items-center gap-3">
                    {STATUS_ICON[f.status]}
                    <span className="text-sm text-white flex-1">{f.name}</span>
                    <span className={`text-xs px-2 py-0.5 rounded border ${SEVERITY_COLOR[f.severity] || ''}`}>{f.severity}</span>
                    {expanded === f.check_id ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
                  </div>
                </button>
                {expanded === f.check_id && (
                  <div className="mt-3 space-y-2 pl-7">
                    <div className="text-sm text-gray-400">{f.description}</div>
                    <div className="bg-gray-800 rounded-lg p-3 space-y-1 text-xs">
                      <div><span className="text-gray-500">Текущее значение: </span><span className="text-red-300">{f.current_value}</span></div>
                      <div><span className="text-gray-500">Ожидаемое: </span><span className="text-green-300">{f.expected_value}</span></div>
                    </div>
                    {f.status !== 'pass' && (
                      <div className="bg-blue-900/20 border border-blue-800 rounded-lg p-3">
                        <div className="text-xs text-blue-300 font-medium mb-1">Рекомендация:</div>
                        <code className="text-xs text-blue-200 block whitespace-pre-wrap">{f.recommendation}</code>
                      </div>
                    )}
                    <div className="flex gap-3 text-xs text-gray-500">
                      {f.cis_control && <span>{f.cis_control}</span>}
                      {f.nist_control && <span>{f.nist_control}</span>}
                    </div>
                  </div>
                )}
              </div>
            ))}
            {selected && findings.length === 0 && (
              <div className="text-center text-gray-500 text-sm py-8">Нет результатов для фильтра</div>
            )}
            {!selected && (
              <div className="text-center text-gray-500 text-sm py-8">Выберите сканирование слева</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
