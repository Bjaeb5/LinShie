import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { Shield, LayoutDashboard, Search, Server, FileText, Users,
         LogOut, Wrench, Zap, Info, Globe, Target, Monitor } from 'lucide-react'
import { useAuth } from '../App'
import { useLang } from '../i18n'

export default function Layout() {
  const { user, logout } = useAuth()
  const { lang, t, setLang } = useLang()
  const navigate = useNavigate()
  const handleLogout = () => { logout(); navigate('/login') }

  const nav = [
    { to: '/',            icon: LayoutDashboard, label: t.nav.dashboard },
    { to: '/osscan',      icon: Monitor,         label: lang === 'ru' ? '🖥️ Сканер ОС' : '🖥️ OS Scanner', highlight: true },
    { to: '/scans',       icon: Search,          label: t.nav.scans },
    { to: '/hosts',       icon: Server,          label: t.nav.hosts },
    { to: '/policies',    icon: FileText,         label: t.nav.policies },
    { to: '/tools',       icon: Wrench,          label: t.nav.tools },
    { to: '/cyberattacks',icon: Zap,             label: t.nav.cyberattacks },
    { to: '/testing',     icon: Target,          label: lang === 'ru' ? 'Тест защиты' : 'Security Testing' },
    { to: '/users',       icon: Users,           label: t.nav.users },
    { to: '/about',       icon: Info,            label: t.nav.about },
  ]

  return (
    <div className="flex h-screen bg-gray-950">
      <aside className="w-60 bg-gray-900 border-r border-gray-800 flex flex-col flex-shrink-0">
        <div className="p-4 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="bg-gradient-to-br from-blue-500 to-cyan-600 p-2 rounded-xl shadow-lg">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="font-bold text-white text-lg tracking-wide">LinShi</div>
              <div className="text-xs text-gray-400">Security Audit v1.1</div>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
          {nav.map(({ to, icon: Icon, label, highlight }) => (
            <NavLink key={to} to={to} end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-blue-600 to-blue-700 text-white shadow-md'
                    : highlight
                    ? 'text-cyan-400 hover:bg-gray-800 hover:text-cyan-300 border border-cyan-900/50'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                }`}>
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span className="truncate">{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="p-3 border-t border-gray-800 space-y-2">
          <div className="flex items-center gap-2 px-2 py-1.5 bg-gray-800 rounded-lg">
            <Globe className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" />
            {(['ru', 'en'] as const).map(l => (
              <button key={l} onClick={() => setLang(l)}
                className={`text-xs px-2 py-0.5 rounded transition-colors ${lang === l ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}>
                {l.toUpperCase()}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2.5 px-2 py-1.5">
            <div className="w-7 h-7 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-full flex items-center justify-center text-xs font-bold text-white flex-shrink-0">
              {user?.username?.[0]?.toUpperCase() || 'A'}
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-xs font-medium text-white truncate">{user?.username || 'Admin'}</div>
              <div className="text-xs text-gray-500 capitalize">{user?.role || 'admin'}</div>
            </div>
          </div>
          <button onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 text-xs text-gray-400 hover:text-red-400 hover:bg-gray-800 rounded-lg transition-colors">
            <LogOut className="w-3.5 h-3.5" />{t.common.logout}
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-auto bg-gray-950">
        <Outlet />
      </main>
    </div>
  )
}
