import { NavLink, useNavigate } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'
import { useIncidentsStore } from '@/store/incidents'
import { authApi } from '@/lib/api'

const nav = [
  { to: '/',           icon: '⬡', label: 'Overview' },
  { to: '/assets',     icon: '◈', label: 'Assets' },
  { to: '/incidents',  icon: '⚡', label: 'Incidents' },
  { to: '/compliance', icon: '⚖', label: 'Compliance' },
  { to: '/shadow-it',  icon: '◌', label: 'Shadow IT' },
]

export function Sidebar() {
  const { user, logout } = useAuthStore()
  const { unreadCount, wsConnected } = useIncidentsStore()
  const navigate = useNavigate()

  const handleLogout = async () => {
    try { await authApi.logout() } catch {}
    logout()
    navigate('/login')
  }

  return (
    <aside className="w-16 lg:w-56 flex flex-col bg-mace-surface border-r border-mace-border flex-shrink-0">
      {/* Logo */}
      <div className="p-4 border-b border-mace-border flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white font-bold text-sm flex-shrink-0">
          M
        </div>
        <div className="hidden lg:block min-w-0">
          <div className="font-bold text-sm text-white truncate">MACE v2</div>
          <div className="text-xs text-slate-500 truncate">{user?.tenant_name}</div>
        </div>
      </div>

      {/* WS indicator */}
      <div className="px-4 py-2 hidden lg:flex items-center gap-2">
        <span className={cn('w-1.5 h-1.5 rounded-full', wsConnected ? 'bg-green-400 animate-pulse' : 'bg-red-400')} />
        <span className="text-xs text-slate-500">{wsConnected ? 'Live' : 'Offline'}</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-2 space-y-1">
        {nav.map(({ to, icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => cn(
              'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all',
              isActive
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            )}
          >
            <span className="text-base flex-shrink-0">{icon}</span>
            <span className="hidden lg:block">{label}</span>
            {label === 'Incidents' && unreadCount > 0 && (
              <span className="hidden lg:flex ml-auto bg-red-500 text-white text-xs rounded-full w-5 h-5 items-center justify-center font-mono">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User / Logout */}
      <div className="p-2 border-t border-mace-border">
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-slate-800 cursor-pointer" onClick={handleLogout}>
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
            {user?.full_name?.[0] || user?.email?.[0] || '?'}
          </div>
          <div className="hidden lg:block min-w-0 flex-1">
            <div className="text-xs text-white truncate">{user?.full_name || user?.email}</div>
            <div className="text-xs text-slate-500 truncate">{user?.role?.replace('_', ' ')}</div>
          </div>
          <span className="hidden lg:block text-slate-500 text-xs">↩</span>
        </div>
      </div>
    </aside>
  )
}
