import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { incidentsApi } from '@/lib/api'
import { SeverityBadge } from '@/components/ui/Badge'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { CDCSMeter } from '@/components/ui/CDCSMeter'
import { Spinner } from '@/components/ui/Spinner'
import { fmtAgo, truncate } from '@/lib/utils'
import type { Incident, IncidentSeverity, IncidentStatus } from '@/types'

interface IncidentTableProps {
  onSelect?: (incident: Incident) => void
}

export function IncidentTable({ onSelect }: IncidentTableProps) {
  const [page, setPage] = useState(1)
  const [filterSeverity, setFilterSeverity] = useState<IncidentSeverity | ''>('')
  const [filterStatus, setFilterStatus] = useState<IncidentStatus | ''>('')
  const [search, setSearch] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['incidents', page, filterSeverity, filterStatus, search],
    queryFn: () => incidentsApi.list({
      page,
      page_size: 50,
      ...(filterSeverity && { severity: filterSeverity }),
      ...(filterStatus && { status: filterStatus }),
      ...(search && { search }),
    }).then(r => r.data),
    refetchInterval: 15_000,
  })

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-2">
        <input
          value={search} onChange={e => { setSearch(e.target.value); setPage(1) }}
          placeholder="Search ref, title, type..."
          className="bg-mace-card border border-mace-border rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 w-64 focus:outline-none focus:border-cyan-500/50"
        />
        <select
          value={filterSeverity}
          onChange={e => { setFilterSeverity(e.target.value as IncidentSeverity | ''); setPage(1) }}
          className="bg-mace-card border border-mace-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500/50"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filterStatus}
          onChange={e => { setFilterStatus(e.target.value as IncidentStatus | ''); setPage(1) }}
          className="bg-mace-card border border-mace-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500/50"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="contained">Contained</option>
          <option value="closed">Closed</option>
          <option value="false_positive">False Positive</option>
        </select>
        {data && <span className="ml-auto text-sm text-slate-500 self-center">{data.total} incidents</span>}
      </div>

      <div className="mace-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-mace-border">
                {['Ref', 'CDCS', 'Severity', 'Status', 'Event Type', 'Kill Chain', 'Frameworks', 'Detected', 'Assigned'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={9} className="text-center py-16"><Spinner /></td></tr>
              ) : data?.items.length === 0 ? (
                <tr><td colSpan={9} className="text-center py-16 text-slate-500">No incidents</td></tr>
              ) : (
                data?.items.map(inc => (
                  <tr
                    key={inc.id}
                    className="border-b border-mace-border hover:bg-slate-800/40 transition-colors cursor-pointer"
                    onClick={() => onSelect?.(inc)}
                  >
                    <td className="px-4 py-3">
                      <div className="font-mono text-xs text-cyan-400">{inc.incident_ref}</div>
                      <div className="text-xs text-slate-500 truncate max-w-[180px]">{truncate(inc.title, 40)}</div>
                    </td>
                    <td className="px-4 py-3 min-w-[120px]">
                      <CDCSMeter score={inc.cdcs_score} size="sm" />
                    </td>
                    <td className="px-4 py-3"><SeverityBadge severity={inc.severity} /></td>
                    <td className="px-4 py-3"><StatusBadge status={inc.status} /></td>
                    <td className="px-4 py-3">
                      <span className="text-xs text-slate-300 font-mono">{inc.event_type}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs text-purple-400 font-mono">{inc.kill_chain_stage || '—'}</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1 max-w-[160px]">
                        {inc.frameworks_triggered.slice(0, 2).map(f => (
                          <span key={f} className="text-xs bg-amber-500/10 text-amber-400 border border-amber-500/20 px-1.5 py-0.5 rounded font-mono">
                            {f.split(' ')[0]}
                          </span>
                        ))}
                        {inc.frameworks_triggered.length > 2 && (
                          <span className="text-xs text-slate-500">+{inc.frameworks_triggered.length - 2}</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs text-slate-500">{fmtAgo(inc.detected_at)}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs text-slate-400">{inc.assigned_to ? truncate(inc.assigned_to, 20) : <span className="text-slate-600">Unassigned</span>}</span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        {data && data.total > 50 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-mace-border">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="px-3 py-1 rounded text-sm text-slate-400 hover:text-white disabled:opacity-30">← Prev</button>
            <span className="text-xs text-slate-500">Page {page}</span>
            <button onClick={() => setPage(p => p + 1)} disabled={!data.has_next}
              className="px-3 py-1 rounded text-sm text-slate-400 hover:text-white disabled:opacity-30">Next →</button>
          </div>
        )}
      </div>
    </div>
  )
}
