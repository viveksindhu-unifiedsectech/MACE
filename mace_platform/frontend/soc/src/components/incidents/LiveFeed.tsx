import { useEffect } from 'react'
import { useIncidentsStore } from '@/store/incidents'
import { useAuthStore } from '@/store/auth'
import { maceWS } from '@/lib/ws'
import { severityBg, fmtTime } from '@/lib/utils'
import { cn } from '@/lib/utils'

export function LiveFeed() {
  const { user } = useAuthStore()
  const { liveEvents, unreadCount, markRead, addLiveEvent, setWsConnected } = useIncidentsStore()

  useEffect(() => {
    if (!user?.tenant_id) return
    maceWS.connect(user.tenant_id)
    setWsConnected(true)
    const unsub = maceWS.onIncident((event) => {
      addLiveEvent(event)
    })
    return () => { unsub(); setWsConnected(false) }
  }, [user?.tenant_id])

  if (liveEvents.length === 0) return null

  return (
    <div className="w-80 flex-shrink-0 bg-mace-surface border-l border-mace-border flex flex-col hidden xl:flex">
      <div className="p-4 border-b border-mace-border flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
        <span className="text-sm font-semibold text-white">Live Incidents</span>
        {unreadCount > 0 && (
          <span className="ml-auto bg-red-500 text-white text-xs rounded-full px-2 py-0.5 cursor-pointer" onClick={markRead}>
            {unreadCount} new
          </span>
        )}
      </div>
      <div className="flex-1 overflow-y-auto">
        {liveEvents.map((e, i) => (
          <div
            key={`${e.incident_ref}-${i}`}
            className={cn(
              'p-3 border-b border-mace-border animate-slide-in hover:bg-slate-800/50 transition-colors',
              i === 0 && 'border-l-2 border-l-red-400'
            )}
          >
            <div className="flex items-start justify-between gap-2 mb-1">
              <span className="font-mono text-xs text-cyan-400">{e.incident_ref}</span>
              <span className="text-xs text-slate-500">{fmtTime(e.ts)}</span>
            </div>
            <div className="flex items-center gap-2 mb-1">
              <span className={cn('text-xs px-1.5 py-0.5 rounded border font-mono', severityBg(e.severity))}>
                {e.severity.toUpperCase()}
              </span>
              <span className="text-xs font-mono text-white">{e.cdcs.toFixed(1)}</span>
            </div>
            <div className="text-xs text-slate-400 truncate">{e.asset}</div>
            <div className="text-xs text-slate-500 truncate">{e.event_type}</div>
            {e.cert_in_reference && (
              <div className="text-xs text-amber-400 font-mono mt-1 truncate">📋 {e.cert_in_reference}</div>
            )}
            {e.aecert_reference && (
              <div className="text-xs text-blue-400 font-mono truncate">📋 {e.aecert_reference}</div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
