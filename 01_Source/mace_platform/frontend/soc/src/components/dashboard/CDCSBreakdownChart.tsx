import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer, Tooltip } from 'recharts'

interface CDCSBreakdownChartProps {
  scores: {
    V: number; E: number; I: number; N: number; C: number; T: number
  }
  title?: string
}

const DOMAIN_LABELS: Record<string, string> = {
  V: 'Vulnerability',
  E: 'Endpoint',
  I: 'Identity',
  N: 'Network',
  C: 'Compliance',
  T: 'Threat Intel',
}

export function CDCSBreakdownChart({ scores, title }: CDCSBreakdownChartProps) {
  const data = Object.entries(scores).map(([key, value]) => ({
    domain: DOMAIN_LABELS[key] || key,
    score: Number((value * 10).toFixed(2)),
    fullMark: 10,
  }))

  return (
    <div className="w-full">
      {title && <div className="text-xs text-slate-500 mb-2 text-center">{title}</div>}
      <ResponsiveContainer width="100%" height={220}>
        <RadarChart data={data}>
          <PolarGrid stroke="#1e2535" />
          <PolarAngleAxis dataKey="domain" tick={{ fill: '#64748b', fontSize: 11 }} />
          <Radar
            dataKey="score" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.15}
            strokeWidth={1.5}
          />
          <Tooltip
            contentStyle={{ background: '#161b24', border: '1px solid #1e2535', borderRadius: 8 }}
            labelStyle={{ color: '#e2e8f0', fontSize: 12 }}
            itemStyle={{ color: '#00d4ff', fontSize: 12, fontFamily: 'monospace' }}
          />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  )
}
