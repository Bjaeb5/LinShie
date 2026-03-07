import { useState, useEffect } from 'react'
import { Plus, Trash2, Play, RefreshCw, Server, X } from 'lucide-react'
import { hostsApi } from '../api'

export default function Hosts() {
  const [hosts, setHosts] = useState<any[]>([])
  const [modal, setModal] = useState(false)
  const [scanning, setScanning] = useState<number | null>(null)
  const [form, setForm] = useState({ name: '', ip_address: '', port: 22, ssh_username: 'root', ssh_password: '', description: '' })

  useEffect(() => { loadHosts() }, [])
  const loadHosts = async () => { const r = await hostsApi.list(); setHosts(r.data) }

  const addHost = async () => {
    await hostsApi.create(form)
    setModal(false); setForm({ name: '', ip_address: '', port: 22, ssh_username: 'root', ssh_password: '', description: '' })
    loadHosts()
  }

  const deleteHost = async (id: number) => {
    if (!confirm('Удалить хост?')) return
    await hostsApi.delete(id); loadHosts()
  }

  const scanHost = async (id: number) => {
    setScanning(id)
    await hostsApi.scan(id)
    const poll = setInterval(async () => {
      const scans = await hostsApi.scans(id)
      const last = scans.data[0]
      if (last && last.status !== 'running') { clearInterval(poll); setScanning(null); loadHosts() }
    }, 2000)
  }

  const scoreColor = (s: number) => s >= 80 ? 'text-green-400' : s >= 60 ? 'text-yellow-400' : 'text-red-400'

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Удалённые хосты</h1>
          <p className="text-gray-400 text-sm">Управление серверами для сканирования</p>
        </div>
        <button onClick={() => setModal(true)}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium">
          <Plus className="w-4 h-4" /> Добавить хост
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {hosts.map(h => (
          <div key={h.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-3">
                <div className="bg-gray-800 p-2 rounded-lg"><Server className="w-5 h-5 text-blue-400" /></div>
                <div>
                  <div className="font-medium text-white">{h.name}</div>
                  <div className="text-xs text-gray-500">{h.ip_address}:{h.port}</div>
                </div>
              </div>
              {h.last_score != null && (
                <span className={`text-2xl font-bold ${scoreColor(h.last_score)}`}>{h.last_score}</span>
              )}
            </div>
            <div className="text-xs text-gray-500 mb-4">
              {h.description && <div className="mb-1">{h.description}</div>}
              <div>Пользователь: {h.ssh_username}</div>
              {h.last_scan && <div>Последнее сканирование: {new Date(h.last_scan).toLocaleString('ru')}</div>}
            </div>
            <div className="flex gap-2">
              <button onClick={() => scanHost(h.id)} disabled={scanning === h.id}
                className="flex-1 flex items-center justify-center gap-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-xs py-2 rounded-lg transition-colors">
                {scanning === h.id ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                {scanning === h.id ? 'Сканируется...' : 'Сканировать'}
              </button>
              <button onClick={() => deleteHost(h.id)}
                className="p-2 bg-gray-800 hover:bg-red-900/30 hover:text-red-400 text-gray-400 rounded-lg transition-colors">
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
        {hosts.length === 0 && (
          <div className="col-span-3 text-center text-gray-500 py-16 text-sm">
            Нет хостов. Добавьте сервер для сканирования.
          </div>
        )}
      </div>

      {/* Modal */}
      {modal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-white">Добавить хост</h2>
              <button onClick={() => setModal(false)}><X className="w-5 h-5 text-gray-400" /></button>
            </div>
            <div className="space-y-3">
              {[
                { label: 'Название', key: 'name', placeholder: 'web-server-01' },
                { label: 'IP-адрес', key: 'ip_address', placeholder: '192.168.1.100' },
                { label: 'SSH порт', key: 'port', placeholder: '22', type: 'number' },
                { label: 'SSH пользователь', key: 'ssh_username', placeholder: 'root' },
                { label: 'SSH пароль', key: 'ssh_password', placeholder: '••••••••', type: 'password' },
                { label: 'Описание', key: 'description', placeholder: 'Веб-сервер' },
              ].map(({ label, key, placeholder, type = 'text' }) => (
                <div key={key}>
                  <label className="block text-xs font-medium text-gray-400 mb-1">{label}</label>
                  <input type={type} placeholder={placeholder} value={(form as any)[key]}
                    onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                    className="w-full bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg text-sm focus:outline-none focus:border-blue-500" />
                </div>
              ))}
            </div>
            <div className="flex gap-3 mt-5">
              <button onClick={() => setModal(false)} className="flex-1 bg-gray-800 text-gray-300 py-2 rounded-lg text-sm">Отмена</button>
              <button onClick={addHost} className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 rounded-lg text-sm font-medium">Добавить</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
