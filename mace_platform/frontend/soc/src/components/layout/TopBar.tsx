import { useAuthStore } from '@/store/auth'
import { useIncidentsStore } from '@/store/incidents'
import { jurisdictionLabel } from '@/lib/utils'

interface TopBarProps { title: string }

export function TopBar({ title }: TopBarProps) {
  const { user } = useAuthStore()
  const { liveEvents } = useIncidentsStore()
  const lastEvent = liveEvents[0]

  return (
    <header className="h-14 bg-mace-surface border-b border-mace-border flex items-center px-6 gap-4 flex-shrink-0">
      <h1 className="font-semibold text-white">{title}</h1>
      <div className="flex-1" />

      {/* Last real-time event */}
      {lastEvent && (
        <div className="hidden md:flex items-center gap-2 text-xs text-slate-500 font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
          <span className="text-red-400">{lastEvent.incident_ref}</span>
          <span>CDCS {lastEvent.cdcs.toFixed(1)}</span>
          <span className="text-slate-600">•</span>
          <span>{lastEvent.asset}</span>
        </div>
      )}

      {/* Jurisdiction pill */}
      <div className="text-xs bg-slate-800 border border-slate-700 px-3 py-1 rounded-full text-slate-300">
        {jurisdictionLabel(user?.jurisdiction || 'US')}
      </div>

      {/* Weight profile */}
      <div className="hidden lg:block text-xs text-slate-500 font-mono">
        {user?.weight_profile}
      </div>
    </header>
  )
}
