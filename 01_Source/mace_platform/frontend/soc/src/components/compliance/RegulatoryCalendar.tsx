import { useQuery } from '@tanstack/react-query'
import { incidentsApi } from '@/lib/api'
import { Spinner } from '@/components/ui/Spinner'
import { fmtDate, fmtHours, jurisdictionLabel } from '@/lib/utils'
import { cn } from '@/lib/utils'
import type { CalendarEntry } from '@/types'

export function RegulatoryCalendar() {
  const { data, isLoading } = useQuery({
    queryKey: ['regulatory-calendar'],
    queryFn: () => incidentsApi.regulatoryCalendar().then(r => r.data),
    refetchInterval: 60_000,
  })

  const entries = data?.items || []
  const breached = entries.filter(e => e.sla_breached)
  const urgent = entries.filter(e => !e.sla_breached && e.hours_remaining < 24)
  const normal = entries.filter(e => !e.sla_breached && e.hours_remaining >= 24)

  if (isLoading) return <div className="flex items-center justify-center py-16"><Spinner /></div>

  if (entries.length === 0) {
    return (
      <div className="mace-card p-12 text-center">
        <div className="text-4xl mb-3">✅</div>
        <div className="text-slate-400 text-sm">No open regulatory reporting obligations</div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-3 gap-4">
        <div className="mace-card p-4 text-center">
          <div className="font-mono text-2xl font-bold text-red-400">{breached.length}</div>
          <div className="text-xs text-slate-500 mt-1">SLA Breached</div>
        </div>
        <div className="mace-card p-4 text-center">
          <div className="font-mono text-2xl font-bold text-amber-400">{urgent.length}</div>
          <div className="text-xs text-slate-500 mt-1">Due &lt;24h</div>
        </div>
        <div className="mace-card p-4 text-center">
          <div className="font-mono text-2xl font-bold text-green-400">{normal.length}</div>
          <div className="text-xs text-slate-500 mt-1">On Track</div>
        </div>
      </div>

      {/* Breached */}
      {breached.length > 0 && (
        <Section title="⚠ SLA BREACHED" entries={breached} urgencyLevel="breached" />
      )}

      {/* Urgent */}
      {urgent.length > 0 && (
        <Section title="⏰ Due within 24 hours" entries={urgent} urgencyLevel="urgent" />
      )}

      {/* Normal */}
      {normal.length > 0 && (
        <Section title="📋 Upcoming Deadlines" entries={normal} urgencyLevel="normal" />
      )}
    </div>
  )
}

function Section({ title, entries, urgencyLevel }: {
  title: string
  entries: CalendarEntry[]
  urgencyLevel: 'breached' | 'urgent' | 'normal'
}) {
  const borderColor = urgencyLevel === 'breached' ? 'border-red-500/30' : urgencyLevel === 'urgent' ? 'border-amber-500/30' : 'border-mace-border'

  return (
    <div className={cn('mace-card overflow-hidden', borderColor)}>
      <div className="px-4 py-3 border-b border-mace-border">
        <span className="text-sm font-medium text-white">{title}</span>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-mace-border">
            {['Incident', 'Framework', 'Jurisdiction', 'Deadline', 'Time Left', 'Status'].map(h => (
              <th key={h} className="px-4 py-2 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {entries.map((entry, i) => (
            <CalendarRow key={`${entry.incident_ref}-${entry.framework}-${i}`} entry={entry} />
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CalendarRow({ entry }: { entry: CalendarEntry }) {
  const urgentClass = entry.sla_breached ? 'text-red-400' : entry.hours_remaining < 24 ? 'text-amber-400' : 'text-green-400'

  return (
    <tr className="border-b border-mace-border hover:bg-slate-800/30 transition-colors">
      <td className="px-4 py-3">
        <span className="font-mono text-xs text-cyan-400">{entry.incident_ref}</span>
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-amber-400 font-mono">{entry.framework}</span>
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-slate-300">{jurisdictionLabel(entry.jurisdiction)}</span>
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-slate-400">{fmtDate(entry.deadline)}</span>
      </td>
      <td className="px-4 py-3">
        <span className={cn('text-xs font-mono font-bold', urgentClass)}>
          {fmtHours(entry.hours_remaining)}
        </span>
      </td>
      <td className="px-4 py-3">
        {entry.sla_breached
          ? <span className="text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded font-mono">BREACHED</span>
          : <span className="text-xs bg-green-500/10 text-green-400 border border-green-500/20 px-2 py-0.5 rounded font-mono">ACTIVE</span>
        }
      </td>
    </tr>
  )
}
