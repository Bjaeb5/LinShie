import { useState, useEffect } from 'react'
import { Plus, Play, Trash2, X, FileText, ChevronDown } from 'lucide-react'
import { policiesApi, hostsApi } from '../api'

const CATEGORIES: Record<string, { label: string; color: string }> = {
  password: { label: 'Пароли', color: 'bg-purple-900/30 text-purple-400 border-purple-800' },
  ssh: { label: 'SSH', color: 'bg-blue-900/30 text-blue-400 border-blue-800' },
  firewall: { label: 'Фаервол', color: 'bg-red-900/30 text-red-400 border-red-800' },
  audit: { label: 'Аудит', color: 'bg-yellow-900/30 text-yellow-400 border-yellow-800' },
  updates: { label: 'Обновления', color: 'bg-green-900/30 text-green-400 border-green-800' },
}

export default function Policies() {
  const [policies, setPolicies] = useState<any[]>([])
  const [hosts, setHosts] = useState<any[]>([])
  const [templates, setTemplates] = useState<any[]>([])
  const [modal, setModal] = useState(false)
  const [applyModal, setApplyModal] = useState<any>(null)
  const [selectedHosts, setSelectedHosts] = useState<number[]>([])
  const [applyResult, setApplyResult] = useState<any>(null)
  const [form, setForm] = useState({ name: '', description: '', category: 'password', rules: {} as any })

  useEffect(() => {
    loadPolicies()
    hostsApi.list().then(r => setHosts(r.data))
    policiesApi.templates().then(r => setTemplates(r.data))
  }, [])

  const loadPolicies = async () => { const r = await policiesApi.list(); setPolicies(r.data) }

  const createPolicy = async () => {
    await policiesApi.create(form)
    setModal(false); loadPolicies()
  }

  const deletePolicy = async (id: number) => {
    if (!confirm('Удалить политику?')) return
    await policiesApi.delete(id); loadPolicies()
  }

  const applyPolicy = async () => {
    const res = await policiesApi.apply(applyModal.id, selectedHosts)
    setApplyResult(res.data)
  }

  const useTemplate = (t: any) => {
    setForm({ name: t.name, description: '', category: t.category, rules: t.rules })
    setModal(true)
  }

  const updateRule = (key: string, value: any) => {
    setForm(f => ({ ...f, rules: { ...f.rules, [key]: value } }))
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Групповые политики</h1>
          <p className="text-gray-400 text-sm">Управление и применение политик безопасности (аналог GPO)</p>
        </div>
        <button onClick={() => setModal(true)} className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium">
          <Plus className="w-4 h-4" /> Создать политику
        </button>
      </div>

      {/* Templates */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
        <h2 className="text-sm font-medium text-gray-400 mb-3">Шаблоны политик</h2>
        <div className="flex flex-wrap gap-2">
          {templates.map((t, i) => (
            <button key={i} onClick={() => useTemplate(t)}
              className={`text-xs px-3 py-1.5 rounded-lg border transition-colors hover:opacity-80 ${CATEGORIES[t.category]?.color || 'bg-gray-800 text-gray-400 border-gray-700'}`}>
              {t.name}
            </button>
          ))}
        </div>
      </div>

      {/* Policies list */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {policies.map(p => (
          <div key={p.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-3">
                <div className="bg-gray-800 p-2 rounded-lg"><FileText className="w-4 h-4 text-blue-400" /></div>
                <div>
                  <div className="font-medium text-white">{p.name}</div>
                  {p.description && <div className="text-xs text-gray-500">{p.description}</div>}
                </div>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded border ${CATEGORIES[p.category]?.color || ''}`}>
                {CATEGORIES[p.category]?.label || p.category}
              </span>
            </div>
            <div className="text-xs text-gray-600 mb-4">{p.created_at ? new Date(p.created_at).toLocaleDateString('ru') : ''}</div>
            <div className="flex gap-2">
              <button onClick={() => { setApplyModal(p); setSelectedHosts([]); setApplyResult(null) }}
                className="flex-1 flex items-center justify-center gap-1.5 bg-green-700 hover:bg-green-600 text-white text-xs py-2 rounded-lg">
                <Play className="w-3 h-3" /> Применить к хостам
              </button>
              <button onClick={() => deletePolicy(p.id)}
                className="p-2 bg-gray-800 hover:bg-red-900/30 hover:text-red-400 text-gray-400 rounded-lg">
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
        {policies.length === 0 && (
          <div className="col-span-2 text-center text-gray-500 py-12 text-sm">
            Нет политик. Создайте или выберите шаблон.
          </div>
        )}
      </div>

      {/* Create Modal */}
      {modal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-white">Создать политику</h2>
              <button onClick={() => setModal(false)}><X className="w-5 h-5 text-gray-400" /></button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-xs font-medium text-gray-400 block mb-1">Название</label>
                <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg text-sm focus:outline-none focus:border-blue-500" />
              </div>
              <div>
                <label className="text-xs font-medium text-gray-400 block mb-1">Категория</label>
                <select value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg text-sm focus:outline-none focus:border-blue-500">
                  {Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                </select>
              </div>

              {/* Dynamic fields by category */}
              {form.category === 'password' && (
                <div className="bg-gray-800 rounded-lg p-4 space-y-3">
                  <div className="text-xs text-gray-400 font-medium">Параметры паролей</div>
                  {[['min_length', 'Минимальная длина', 12], ['max_age', 'Макс. срок (дней)', 90]].map(([k, l, d]) => (
                    <div key={String(k)}>
                      <label className="text-xs text-gray-500 block mb-1">{String(l)}</label>
                      <input type="number" defaultValue={form.rules[String(k)] ?? d}
                        onChange={e => updateRule(String(k), +e.target.value)}
                        className="w-full bg-gray-700 border border-gray-600 text-white px-3 py-1.5 rounded text-sm" />
                    </div>
                  ))}
                </div>
              )}
              {form.category === 'ssh' && (
                <div className="bg-gray-800 rounded-lg p-4 space-y-3">
                  <div className="text-xs text-gray-400 font-medium">Параметры SSH</div>
                  {[['permit_root', 'PermitRootLogin', 'no'], ['password_auth', 'PasswordAuthentication', 'no'],
                    ['max_auth_tries', 'MaxAuthTries', '4'], ['idle_timeout', 'ClientAliveInterval (сек)', '300']].map(([k, l, d]) => (
                    <div key={String(k)}>
                      <label className="text-xs text-gray-500 block mb-1">{String(l)}</label>
                      <input defaultValue={form.rules[String(k)] ?? d}
                        onChange={e => updateRule(String(k), e.target.value)}
                        className="w-full bg-gray-700 border border-gray-600 text-white px-3 py-1.5 rounded text-sm" />
                    </div>
                  ))}
                </div>
              )}
              {form.category === 'firewall' && (
                <div className="bg-gray-800 rounded-lg p-4">
                  <label className="text-xs text-gray-400 block mb-1">Разрешённые порты (через запятую)</label>
                  <input defaultValue={(form.rules.allowed_ports || ['22','80','443']).join(',')}
                    onChange={e => updateRule('allowed_ports', e.target.value.split(',').map(s => s.trim()))}
                    className="w-full bg-gray-700 border border-gray-600 text-white px-3 py-1.5 rounded text-sm"
                    placeholder="22,80,443" />
                </div>
              )}
              {(form.category === 'audit' || form.category === 'updates') && (
                <div className="bg-gray-800 rounded-lg p-3 text-xs text-gray-400">
                  Политика применит стандартную конфигурацию {form.category === 'audit' ? 'auditd' : 'unattended-upgrades'} на хосты.
                </div>
              )}
            </div>
            <div className="flex gap-3 mt-5">
              <button onClick={() => setModal(false)} className="flex-1 bg-gray-800 text-gray-300 py-2 rounded-lg text-sm">Отмена</button>
              <button onClick={createPolicy} className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 rounded-lg text-sm font-medium">Создать</button>
            </div>
          </div>
        </div>
      )}

      {/* Apply Modal */}
      {applyModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-white">Применить: {applyModal.name}</h2>
              <button onClick={() => setApplyModal(null)}><X className="w-5 h-5 text-gray-400" /></button>
            </div>
            {!applyResult ? (
              <>
                <p className="text-sm text-gray-400 mb-4">Выберите хосты для применения политики:</p>
                <div className="space-y-2 max-h-48 overflow-y-auto mb-4">
                  {hosts.map(h => (
                    <label key={h.id} className="flex items-center gap-3 p-3 bg-gray-800 rounded-lg cursor-pointer hover:bg-gray-750">
                      <input type="checkbox" checked={selectedHosts.includes(h.id)}
                        onChange={e => setSelectedHosts(prev => e.target.checked ? [...prev, h.id] : prev.filter(id => id !== h.id))}
                        className="rounded" />
                      <span className="text-sm text-white">{h.name}</span>
                      <span className="text-xs text-gray-500 ml-auto">{h.ip_address}</span>
                    </label>
                  ))}
                  {hosts.length === 0 && <div className="text-center text-gray-500 text-sm py-4">Нет хостов</div>}
                </div>
                <div className="flex gap-3">
                  <button onClick={() => setApplyModal(null)} className="flex-1 bg-gray-800 text-gray-300 py-2 rounded-lg text-sm">Отмена</button>
                  <button onClick={applyPolicy} disabled={selectedHosts.length === 0}
                    className="flex-1 bg-green-700 hover:bg-green-600 disabled:opacity-60 text-white py-2 rounded-lg text-sm font-medium">
                    Применить ({selectedHosts.length})
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {applyResult.results?.map((r: any, i: number) => (
                    <div key={i} className={`p-3 rounded-lg text-sm ${r.success ? 'bg-green-900/20 border border-green-800' : 'bg-red-900/20 border border-red-800'}`}>
                      <span className={r.success ? 'text-green-400' : 'text-red-400'}>{r.success ? '✓' : '✗'}</span>
                      <span className="text-white ml-2">{r.host_name || `Хост #${r.host_id}`}</span>
                      {r.error && <div className="text-xs text-red-300 mt-1">{r.error}</div>}
                    </div>
                  ))}
                </div>
                <button onClick={() => setApplyModal(null)} className="w-full bg-gray-800 text-gray-300 py-2 rounded-lg text-sm mt-4">Закрыть</button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
