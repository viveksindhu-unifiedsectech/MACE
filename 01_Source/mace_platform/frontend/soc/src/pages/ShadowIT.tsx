import { useQuery } from '@tanstack/react-query'
import { assetsApi } from '@/lib/api'
import { Layout } from '@/components/layout/Layout'
import { ACSIndicator } from '@/components/ui/ACSIndicator'
import { Spinner } from '@/components/ui/Spinner'
import { fmtAgo } from '@/lib/utils'

export default function ShadowIT() {
  const { data: shadowIt, isLoading: siLoading } = useQuery({
    queryKey: ['shadow-it'],
    queryFn: () => assetsApi.shadowIt().then(r => r.data),
    refetchInterval: 60_000,
  })

  const { data: geoAnomalies, isLoading: geoLoading } = useQuery({
    queryKey: ['geo-anomalies'],
    queryFn: () => assetsApi.geoAnomalies().then(r => r.data),
    refetchInterval: 60_000,
  })

  return (
    <Layout title="Shadow IT & Geo Anomalies">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Shadow IT */}
        <div>
          <div className="flex items-center gap-2 mb-4">
            <span className="text-orange-400">◌</span>
            <h2 className="text-white font-semibold">Shadow IT Assets</h2>
            {shadowIt && (
              <span className="ml-auto text-xs bg-orange-500/10 text-orange-400 border border-orange-500/20 px-2 py-0.5 rounded font-mono">
                {shadowIt.count} detected
              </span>
            )}
          </div>
          <div className="mace-card overflow-hidden">
            {siLoading ? (
              <div className="flex items-center justify-center py-12"><Spinner /></div>
            ) : shadowIt?.count === 0 ? (
              <div className="text-center py-12 text-slate-500">
                <div className="text-3xl mb-2">✅</div>
                <div className="text-sm">No shadow IT detected</div>
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-mace-border">
                    {['Asset', 'Class', 'ACS', 'Entropy', 'Last Seen'].map(h => (
                      <th key={h} className="px-4 py-2 text-left text-xs text-slate-500 uppercase">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {shadowIt?.assets?.map((a: { id: string; canonical_id: string; ip_address: string; asset_class: string; entropy_score: number; acs_score?: number; last_seen_at: string }) => (
                    <tr key={a.id} className="border-b border-mace-border hover:bg-slate-800/30">
                      <td className="px-4 py-3">
                        <div className="font-mono text-xs text-orange-400">{a.ip_address || a.canonical_id.slice(0,12)}</div>
                        <div className="text-xs text-slate-500">{a.canonical_id.slice(0,8)}</div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{a.asset_class}</td>
                      <td className="px-4 py-3">
                        <ACSIndicator score={a.acs_score || 0.1} />
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-red-400">{a.entropy_score.toFixed(2)}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs text-slate-500">{fmtAgo(a.last_seen_at)}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Geo Anomalies */}
        <div>
          <div className="flex items-center gap-2 mb-4">
            <span className="text-red-400">⚡</span>
            <h2 className="text-white font-semibold">Geo-Velocity Anomalies</h2>
            {geoAnomalies && (
              <span className="ml-auto text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded font-mono">
                {geoAnomalies.count} detected
              </span>
            )}
          </div>
          <div className="mace-card overflow-hidden">
            {geoLoading ? (
              <div className="flex items-center justify-center py-12"><Spinner /></div>
            ) : geoAnomalies?.count === 0 ? (
              <div className="text-center py-12 text-slate-500">
                <div className="text-3xl mb-2">✅</div>
                <div className="text-sm">No geo anomalies detected</div>
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-mace-border">
                    {['Asset', 'Max Velocity', 'Last Location'].map(h => (
                      <th key={h} className="px-4 py-2 text-left text-xs text-slate-500 uppercase">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {geoAnomalies?.assets?.map((a: { id: string; hostname?: string; ip_address?: string; max_velocity_kmh: number; last_city?: string; last_country?: string }) => (
                    <tr key={a.id} className="border-b border-mace-border hover:bg-slate-800/30">
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-white">{a.hostname || a.ip_address}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-red-400 font-bold">
                          {a.max_velocity_kmh.toLocaleString()} km/h
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs text-slate-400">
                          {a.last_city}{a.last_city && a.last_country ? ', ' : ''}{a.last_country}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </Layout>
  )
}
