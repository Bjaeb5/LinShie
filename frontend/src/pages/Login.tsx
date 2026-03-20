import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Lock, User, AlertCircle, Globe } from 'lucide-react'
import { authApi } from '../api'
import { useAuth } from '../App'
import { useLang } from '../i18n'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const { setUser } = useAuth()
  const { lang, t, setLang } = useLang()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(''); setLoading(true)
    try {
      const res = await authApi.login(username, password)
      localStorage.setItem('access_token', res.data.access_token)
      setUser(res.data.user)
      navigate('/')
    } catch {
      setError(t.login.error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 left-1/3 w-64 h-64 bg-cyan-600/10 rounded-full blur-3xl" />
      </div>

      {/* Lang switcher top right */}
      <div className="absolute top-4 right-4 flex items-center gap-2 bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5">
        <Globe className="w-3.5 h-3.5 text-gray-400" />
        {(['ru', 'en'] as const).map(l => (
          <button key={l} onClick={() => setLang(l)}
            className={`text-xs px-2 py-0.5 rounded transition-colors ${lang === l ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}>
            {l.toUpperCase()}
          </button>
        ))}
      </div>

      <div className="w-full max-w-md relative z-10">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-blue-500 to-cyan-600 rounded-2xl mb-4 shadow-2xl shadow-blue-900/50">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-4xl font-bold text-white tracking-tight">LinShi</h1>
          <p className="text-gray-400 mt-2 text-sm">{t.appDesc}</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 shadow-2xl">
          <h2 className="text-xl font-semibold text-white mb-6">{t.login.title}</h2>
          {error && (
            <div className="flex items-center gap-2 bg-red-900/30 border border-red-800 text-red-400 rounded-lg px-4 py-3 mb-4 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />{error}
            </div>
          )}
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">{t.login.username}</label>
              <div className="relative">
                <User className="absolute left-3 top-3 w-4 h-4 text-gray-500" />
                <input type="text" value={username} onChange={e => setUsername(e.target.value)}
                  placeholder="admin"
                  className="w-full bg-gray-800 border border-gray-700 text-white pl-10 pr-4 py-2.5 rounded-lg focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
                  required />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">{t.login.password}</label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 w-4 h-4 text-gray-500" />
                <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-gray-800 border border-gray-700 text-white pl-10 pr-4 py-2.5 rounded-lg focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
                  required />
              </div>
            </div>
            <button type="submit" disabled={loading}
              className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 disabled:opacity-60 text-white font-medium py-2.5 rounded-lg transition-all shadow-lg shadow-blue-900/30 mt-2">
              {loading ? t.login.loading : t.login.submit}
            </button>
          </form>
          <div className="mt-6 pt-4 border-t border-gray-800 flex flex-wrap gap-2">
            {['CIS Benchmarks', 'NIST SP 800-53', 'OWASP Top 10'].map(s => (
              <span key={s} className="bg-gray-800 text-gray-400 px-2 py-1 rounded text-xs border border-gray-700">{s}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
