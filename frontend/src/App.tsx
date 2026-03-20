import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useState, createContext, useContext } from 'react'
import { LangProvider } from './i18n'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import Hosts from './pages/Hosts'
import Policies from './pages/Policies'
import Users from './pages/Users'
import Tools from './pages/Tools'
import CyberAttacks from './pages/CyberAttacks'
import About from './pages/About'
import SecurityTesting from './pages/SecurityTesting'
import OSScan from './pages/OSScan'
import Layout from './components/Layout'

interface AuthCtx { user: any; setUser: (u: any) => void; logout: () => void }
export const AuthContext = createContext<AuthCtx>({ user: null, setUser: () => {}, logout: () => {} })
export const useAuth = () => useContext(AuthContext)

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('access_token')
  return token ? <>{children}</> : <Navigate to="/login" replace />
}

export default function App() {
  const [user, setUser] = useState<any>(null)
  const logout = () => { localStorage.removeItem('access_token'); setUser(null) }
  return (
    <LangProvider>
      <AuthContext.Provider value={{ user, setUser, logout }}>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
              <Route index element={<Dashboard />} />
              <Route path="scans" element={<Scans />} />
              <Route path="hosts" element={<Hosts />} />
              <Route path="policies" element={<Policies />} />
              <Route path="tools" element={<Tools />} />
              <Route path="cyberattacks" element={<CyberAttacks />} />
              <Route path="testing" element={<SecurityTesting />} />
              <Route path="osscan" element={<OSScan />} />
              <Route path="users" element={<Users />} />
              <Route path="about" element={<About />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthContext.Provider>
    </LangProvider>
  )
}
