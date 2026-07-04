import { NavLink, useNavigate } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'
import { authApi } from '@/lib/api'

const nav = [
  { to: '/',            icon: '⬡', label: 'Dashboard' },
  { to: '/tenant',      icon: '🏢', label: 'Tenant Config' },
  { to: '/users',       icon: '👥', label: 'Users' },
  { to: '/api-keys',    icon: '🔑', label: 'API Keys' },
  { to: '/connectors',  icon: '🔌', label: 'Connectors' },
  { to: '/billing',     icon: '💳', label: 'Billing' },
  { to: '/audit',       icon: '📋', label: 'Audit Log' },
]

export function Sidebar() {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()
  const handleLogout = async () => { try { await authApi.logout() } catch {}; logout(); navigate('/login') }

  return (
    <aside className="w-56 flex flex-col bg-adm-surface border-r border-adm-border flex-shrink-0">
      <div className="p-4 border-b border-adm-border flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white font-bold text-sm flex-shrink-0">A</div>
        <div className="min-w-0">
          <div className="font-bold text-sm text-white">MACE Admin</div>
          <div className="text-xs text-adm-muted truncate">{user?.tenant_name}</div>
        </div>
      </div>
      <nav className="flex-1 p-2 space-y-0.5">
        {nav.map(({ to, icon, label }) => (
          <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => cn(
            'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all',
            isActive ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'text-adm-muted hover:text-white hover:bg-adm-card'
          )}>
            <span>{icon}</span><span>{label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="p-2 border-t border-adm-border">
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-adm-card cursor-pointer" onClick={handleLogout}>
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center text-white text-xs font-bold">
            {user?.full_name?.[0] || '?'}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs text-white truncate">{user?.email}</div>
            <div className="text-xs text-adm-muted">{user?.role?.replace('_',' ')}</div>
          </div>
          <span className="text-adm-muted text-xs">↩</span>
        </div>
      </div>
    </aside>
  )
}
