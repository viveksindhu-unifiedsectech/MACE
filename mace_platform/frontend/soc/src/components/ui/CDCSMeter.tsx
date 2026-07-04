import { cdcsColor } from '@/lib/utils'

interface CDCSMeterProps {
  score: number
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
}

export function CDCSMeter({ score, size = 'md', showLabel = true }: CDCSMeterProps) {
  const color = cdcsColor(score)
  const pct = (score / 10) * 100
  const sizes = { sm: 'h-1.5', md: 'h-2', lg: 'h-3' }
  const textSizes = { sm: 'text-sm', md: 'text-base', lg: 'text-xl' }

  return (
    <div className="flex items-center gap-3">
      {showLabel && (
        <span className={`font-mono font-bold ${textSizes[size]}`} style={{ color }}>
          {score.toFixed(1)}
        </span>
      )}
      <div className={`flex-1 bg-slate-800 rounded-full ${sizes[size]} overflow-hidden`}>
        <div
          className={`h-full rounded-full transition-all duration-700`}
          style={{ width: `${pct}%`, backgroundColor: color, boxShadow: `0 0 6px ${color}60` }}
        />
      </div>
      {showLabel && <span className="text-xs text-slate-500">/10</span>}
    </div>
  )
}

interface DonutScoreProps {
  score: number
  label?: string
  size?: number
}

export function DonutScore({ score, label, size = 64 }: DonutScoreProps) {
  const color = cdcsColor(score)
  const r = (size - 8) / 2
  const circ = 2 * Math.PI * r
  const dash = (score / 10) * circ

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1e2535" strokeWidth={6} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color}
          strokeWidth={6} strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`}
          style={{ filter: `drop-shadow(0 0 4px ${color}80)`, transition: 'stroke-dasharray 0.7s ease' }}
        />
      </svg>
      <div className="absolute text-center">
        <div className="font-mono font-bold text-sm leading-none" style={{ color }}>{score.toFixed(1)}</div>
        {label && <div className="text-xs text-slate-500 mt-0.5">{label}</div>}
      </div>
    </div>
  )
}
