import { useQuery } from '@tanstack/react-query'
import { adminApi } from '@/lib/api'
import { Layout } from '@/components/layout/Layout'
import { StatCard, Spinner } from '@/components/ui'
import { useAuthStore } from '@/store/auth'
import { planLabel, jurisdictionLabel, fmtHours } from '@/lib/utils'

export default function Dashboard() {
  const { user } = useAuthStore()
  const { data: stats, isLoading } = useQuery({
    queryKey:['stats'],
    queryFn: () => adminApi.stats().then(r => r.data),
    refetchInterval: 60_000
  })
  const { data: tenant } = useQuery({ queryKey:['tenant'], queryFn: () => adminApi.tenant().then(r=>r.data) })

  return (
    <Layout title="Dashboard">
      {isLoading ? <div className="flex justify-center py-20"><Spinner /></div> : (
        <div className="space-y-6 animate-fade-in">
          {/* Welcome */}
          <div className="adm-card p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-white">{user?.tenant_name}</h2>
                <div className="text-adm-muted text-sm mt-1">{jurisdictionLabel(user?.jurisdiction||'US')} · {user?.weight_profile}</div>
              </div>
              <div className="text-right">
                <div className="text-sm text-white">{planLabel(user?.plan||'starter')}</div>
                <div className="text-xs text-adm-muted mt-1">{user?.email} · {user?.role?.replace('_',' ')}</div>
              </div>
            </div>
          </div>

          {/* Key metrics */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="Total Assets" value={stats?.assets.total?.toLocaleString()||'0'} sub={`${stats?.assets.limit} limit`} icon="◈" color="#6366f1"/>
            <StatCard label="Open Incidents" value={stats?.incidents.open||0} sub={`${stats?.incidents.critical||0} critical`} icon="⚡" color={stats?.incidents.critical ? '#ef4444' : '#e2e8f0'}/>
            <StatCard label="Open Vulns" value={stats?.vulnerabilities.open?.toLocaleString()||'0'} icon="🔓" color="#f59e0b"/>
            <StatCard label="Alert Rate" value={`${(((stats?.engine as Record<string,number>)?.alert_rate||0)*100).toFixed(1)}%`} icon="📊" color="#10b981"/>
          </div>

          {/* MACE engine health */}
          {stats?.engine && Object.keys(stats.engine).length > 0 && (
            <div className="adm-card p-6">
              <h3 className="font-semibold text-white mb-4">MACE Engine Health</h3>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                {Object.entries(stats.engine as Record<string,unknown>).slice(0, 8).map(([k, v]) => (
                  <div key={k} className="bg-adm-bg rounded-lg p-3 border border-adm-border">
                    <div className="text-xs text-adm-muted mb-1">{k.replace(/_/g,' ')}</div>
                    <div className="text-sm font-mono text-white">
                      {typeof v === 'number' ? (v % 1 !== 0 ? v.toFixed(3) : v) : String(v)}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Regulatory calendar preview */}
          {stats?.regulatory_calendar && (stats.regulatory_calendar as unknown[]).length > 0 && (
            <div className="adm-card p-6">
              <h3 className="font-semibold text-white mb-4">⚖ Regulatory Calendar (next 5)</h3>
              <div className="space-y-2">
                {(stats.regulatory_calendar as Array<{incident_ref:string; framework:string; hours_remaining:number; sla_breached:boolean}>).slice(0,5).map((e, i) => (
                  <div key={i} className="flex items-center gap-3 py-2 border-b border-adm-border last:border-0">
                    <span className={`text-xs font-mono px-2 py-0.5 rounded border ${e.sla_breached ? 'text-red-400 bg-red-500/10 border-red-500/20' : e.hours_remaining < 24 ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' : 'text-green-400 bg-green-500/10 border-green-500/20'}`}>
                      {fmtHours(e.hours_remaining)}
                    </span>
                    <span className="font-mono text-xs text-indigo-400">{e.incident_ref}</span>
                    <span className="text-xs text-amber-400 flex-1">{e.framework}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Layout>
  )
}
