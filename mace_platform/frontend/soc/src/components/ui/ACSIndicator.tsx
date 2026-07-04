import { acsColor } from '@/lib/utils'

interface ACSIndicatorProps {
  score: number
  showValue?: boolean
}

export function ACSIndicator({ score, showValue = true }: ACSIndicatorProps) {
  const color = acsColor(score)
  const bars = Math.round(score * 5)

  return (
    <div className="flex items-center gap-1.5">
      <div className="flex gap-0.5">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className="w-1 rounded-sm transition-all duration-300"
            style={{
              height: `${8 + i * 2}px`,
              backgroundColor: i < bars ? color : '#1e2535',
              boxShadow: i < bars ? `0 0 4px ${color}60` : 'none',
            }}
          />
        ))}
      </div>
      {showValue && (
        <span className="font-mono text-xs" style={{ color }}>
          {(score * 100).toFixed(0)}%
        </span>
      )}
    </div>
  )
}
