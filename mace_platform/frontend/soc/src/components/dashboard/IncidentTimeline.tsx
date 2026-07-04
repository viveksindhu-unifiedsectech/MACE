import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { format, subDays } from 'date-fns'

interface IncidentTimelineProps {
  incidents: Array<{ detected_at: string; severity: string }>
}

export function IncidentTimeline({ incidents }: IncidentTimelineProps) {
  // Build last-7-day buckets
  const days = Array.from({ length: 7 }, (_, i) => {
    const d = subDays(new Date(), 6 - i)
    const label = format(d, 'EEE')
    const dayStr = format(d, 'yyyy-MM-dd')
    const count = incidents.filter(inc => inc.detected_at.startsWith(dayStr)).length
    const critical = incidents.filter(i => i.detected_at.startsWith(dayStr) && i.severity === 'critical').length
    return { label, count, critical }
  })

  return (
    <ResponsiveContainer width="100%" height={120}>
      <BarChart data={days} barSize={24}>
        <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis hide />
        <Tooltip
          contentStyle={{ background: '#161b24', border: '1px solid #1e2535', borderRadius: 8 }}
          labelStyle={{ color: '#e2e8f0', fontSize: 12 }}
          itemStyle={{ fontSize: 12, fontFamily: 'monospace' }}
        />
        <Bar dataKey="count" name="Incidents" radius={[3, 3, 0, 0]}>
          {days.map((d, i) => (
            <Cell key={i} fill={d.critical > 0 ? '#ff4d4f' : d.count > 0 ? '#fa8c16' : '#1e2535'} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
