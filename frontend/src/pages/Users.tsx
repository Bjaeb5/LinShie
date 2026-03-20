import { useState, useEffect } from 'react'
import { Plus, Trash2, X, User, Shield, Eye } from 'lucide-react'
import { usersApi } from '../api'

const ROLE_COLOR: Record<string, string> = {
  admin: 'bg-red-900/30 text-red-400 border-red-800',
  operator: 'bg-blue-900/30 text-blue-400 border-blue-800',
  viewer: 'bg-gray-700 text-gray-400 border-gray-600',
}
const ROLE_ICON: Record<string, React.ReactNode> = {
  admin: <Shield className="w-3 h-3" />,
  operator: <User className="w-3 h-3" />,
  viewer: <Eye className="w-3 h-3" />,
}

export default function Users() {
  const [users, setUsers] = useState<any[]>([])
  const [modal, setModal] = useState(false)
  const [form, setForm] = useState({ username: '', email: '', password: '', role: 'viewer' })

  useEffect(() => { loadUsers() }, [])
  const loadUsers = async () => { const r = await usersApi.list(); setUsers(r.data) }

  const createUser = async () => {
    try {
      await usersApi.create(form)
      setModal(false); setForm({ username: '', email: '', password: '', role: 'viewer' }); loadUsers()
    } catch (e: any) { alert(e.response?.data?.detail || 'Ошибка') }
  }

  const toggleActive = async (u: any) => {
    await usersApi.update(u.id, { is_active: !u.is_active }); loadUsers()
  }

  const deleteUser = async (id: number) => {
    if (!confirm('Удалить пользователя?')) return
    await usersApi.delete(id); loadUsers()
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Пользователи</h1>
          <p className="text-gray-400 text-sm">Управление доступом к системе</p>
        </div>
        <button onClick={() => setModal(true)} className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium">
          <Plus className="w-4 h-4" /> Добавить пользователя
        </button>
      </div>

      {/* Roles description */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { role: 'admin', title: 'Администратор', desc: 'Полный доступ: управление пользователями, политиками, сканирования' },
          { role: 'operator', title: 'Оператор', desc: 'Запуск сканирований, просмотр результатов, управление хостами' },
          { role: 'viewer', title: 'Наблюдатель', desc: 'Только просмотр результатов и отчётов' },
        ].map(r => (
          <div key={r.role} className={`border rounded-xl p-4 ${ROLE_COLOR[r.role]}`}>
            <div className="flex items-center gap-2 font-medium mb-1">{ROLE_ICON[r.role]}{r.title}</div>
            <div className="text-xs opacity-80">{r.desc}</div>
          </div>
        ))}
      </div>

      {/* Users table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              {['Пользователь', 'Email', 'Роль', 'Статус', 'Последний вход', 'Действия'].map(h => (
                <th key={h} className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {users.map(u => (
              <tr key={u.id} className="hover:bg-gray-800/50 transition-colors">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-gray-700 rounded-full flex items-center justify-center text-sm font-bold text-white">
                      {u.username[0].toUpperCase()}
                    </div>
                    <span className="text-sm text-white font-medium">{u.username}</span>
                  </div>
                </td>
                <td className="px-4 py-3 text-sm text-gray-400">{u.email}</td>
                <td className="px-4 py-3">
                  <span className={`text-xs px-2 py-0.5 rounded border inline-flex items-center gap-1 ${ROLE_COLOR[u.role] || ''}`}>
                    {ROLE_ICON[u.role]}{u.role}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <button onClick={() => toggleActive(u)}
                    className={`text-xs px-2 py-0.5 rounded ${u.is_active ? 'bg-green-900/30 text-green-400' : 'bg-gray-700 text-gray-500'}`}>
                    {u.is_active ? 'Активен' : 'Отключён'}
                  </button>
                </td>
                <td className="px-4 py-3 text-xs text-gray-500">
                  {u.last_login ? new Date(u.last_login).toLocaleString('ru') : 'Никогда'}
                </td>
                <td className="px-4 py-3">
                  <button onClick={() => deleteUser(u.id)}
                    className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-red-900/20 rounded transition-colors">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {users.length === 0 && <div className="text-center text-gray-500 text-sm py-8">Нет пользователей</div>}
      </div>

      {/* Modal */}
      {modal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-white">Новый пользователь</h2>
              <button onClick={() => setModal(false)}><X className="w-5 h-5 text-gray-400" /></button>
            </div>
            <div className="space-y-3">
              {[
                { label: 'Логин', key: 'username', placeholder: 'ivan.petrov', type: 'text' },
                { label: 'Email', key: 'email', placeholder: 'ivan@company.local', type: 'email' },
                { label: 'Пароль', key: 'password', placeholder: '••••••••', type: 'password' },
              ].map(({ label, key, placeholder, type }) => (
                <div key={key}>
                  <label className="text-xs font-medium text-gray-400 block mb-1">{label}</label>
                  <input type={type} placeholder={placeholder} value={(form as any)[key]}
                    onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                    className="w-full bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg text-sm focus:outline-none focus:border-blue-500" />
                </div>
              ))}
              <div>
                <label className="text-xs font-medium text-gray-400 block mb-1">Роль</label>
                <select value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg text-sm focus:outline-none focus:border-blue-500">
                  <option value="viewer">Наблюдатель</option>
                  <option value="operator">Оператор</option>
                  <option value="admin">Администратор</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3 mt-5">
              <button onClick={() => setModal(false)} className="flex-1 bg-gray-800 text-gray-300 py-2 rounded-lg text-sm">Отмена</button>
              <button onClick={createUser} className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 rounded-lg text-sm font-medium">Создать</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
