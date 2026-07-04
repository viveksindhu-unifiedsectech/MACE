import { useQuery } from '@tanstack/react-query'
import { adminApi } from '@/lib/api'
import { Layout } from '@/components/layout/Layout'
import { StatCard } from '@/components/dashboard/StatCard'
import { IncidentTimeline } from '@/components/dashboard/IncidentTimeline'
import { CDCSBreakdownChart } from '@/components/dashboard/CDCSBreakdownChart'
import { Spinner } from '@/components/ui/Spinner'
import { cdcsColor, fmtHours } from '@/lib/utils'

export default function Overview() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: () => adminApi.stats().then(r => r.data),
    refetchInterval: 30_000,
  })

  const { data: incidents } = useQuery({
    queryKey: ['incidents-all'],
    queryFn: () => import('@/lib/api').then(m => m.incidentsApi.list({ page_size: 200 }).then(r => r.data)),
    refetchInterval: 60_000,
  })

  if (isLoading) return (
    <Layout title="Overview">
      <div className="flex items-center justify-center h-64"><Spinner /></div>
    </Layout>
  )

  const engine = stats?.engine
  const urgentCalendar = stats?.regulatory_calendar.filter(e => !e.sla_breached && e.hours_remaining < 24) || []
  const breachedCalendar = stats?.regulatory_calendar.filter(e => e.sla_breached) || []

  // Build mock sub-scores from engine weights for visualization
  const mockSubScores = engine ? {
    V: (engine.current_weights?.alpha || 0.28) * 3,
    E: (engine.current_weights?.beta || 0.22) * 3,
    I: (engine.current_weights?.gamma || 0.20) * 3,
    N: (engine.current_weights?.delta || 0.12) * 3,
    C: (engine.current_weights?.epsilon || 0.10) * 3,
    T: (engine.current_weights?.zeta || 0.08) * 3,
  } : { V: 0.84, E: 0.66, I: 0.60, N: 0.36, C: 0.30, T: 0.24 }

  return (
    <Layout title="SOC Overview">
      {/* Alert banners */}
      {breachedCalendar.length > 0 && (
        <div className="mb-4 bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center gap-3">
          <span className="text-red-400 text-xl">⚠</span>
          <div>
            <div className="text-red-400 font-semibold text-sm">{breachedCalendar.length} SLA Breach{breachedCalendar.length > 1 ? 'es' : ''}</div>
            <div className="text-red-400/70 text-xs">Regulatory reporting deadlines passed. Immediate action required.</div>
          </div>
        </div>
      )}

      {/* Key stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Assets" value={stats?.assets.total?.toLocaleString() || '0'}
          sub={`${stats?.assets.limit?.toLocaleString()} limit`} icon="◈" color="#00d4ff" />
        <StatCard label="Open Incidents" value={stats?.incidents.open || 0}
          color={stats?.incidents.critical ? '#ff4d4f' : '#e2e8f0'}
          sub={`${stats?.incidents.critical || 0} critical`} icon="⚡" urgent={(stats?.incidents.open || 0) > 0} />
        <StatCard label="Open Vulns" value={stats?.vulnerabilities.open?.toLocaleString() || '0'}
          icon="🔓" color="#fa8c16" />
        <StatCard label="Alert Rate" value={`${((engine?.alert_rate || 0) * 100).toFixed(1)}%`}
          sub={`TP rate: ${((engine?.true_positive_rate || 0) * 100).toFixed(0)}%`}
          icon="📊" color="#52c41a" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Incident timeline */}
        <div className="lg:col-span-2 mace-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="text-sm font-semibold text-white">Incident Activity (7 days)</div>
            <div className="text-xs text-slate-500 font-mono">{engine?.weight_profile}</div>
          </div>
          <IncidentTimeline incidents={incidents?.items || []} />
        </div>

        {/* CDCS Weight Profile */}
        <div className="mace-card p-5">
          <div className="text-sm font-semibold text-white mb-1">Active Weight Profile</div>
          <div className="text-xs text-slate-500 mb-3">{engine?.weight_profile || 'usa_fedramp'}</div>
          <CDCSBreakdownChart scores={mockSubScores} />
        </div>
      </div>

      {/* Regulatory Calendar preview */}
      {stats?.regulatory_calendar && stats.regulatory_calendar.length > 0 && (
        <div className="mace-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="text-sm font-semibold text-white">⚖ Regulatory Calendar</div>
            <a href="/compliance" className="text-xs text-cyan-400 hover:text-cyan-300">View all →</a>
          </div>
          <div className="space-y-2">
            {stats.regulatory_calendar.slice(0, 5).map((entry, i) => (
              <div key={i} className="flex items-center gap-3 py-2 border-b border-mace-border last:border-0">
                <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
                  entry.sla_breached ? 'text-red-400 bg-red-500/10 border-red-500/20'
                  : entry.hours_remaining < 24 ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                  : 'text-green-400 bg-green-500/10 border-green-500/20'
                }`}>
                  {fmtHours(entry.hours_remaining)}
                </span>
                <span className="font-mono text-xs text-cyan-400">{entry.incident_ref}</span>
                <span className="text-xs text-amber-400 flex-1 truncate">{entry.framework}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Layout>
  )
}
