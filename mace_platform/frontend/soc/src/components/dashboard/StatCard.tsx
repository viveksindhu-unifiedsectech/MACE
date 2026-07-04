import { cn } from '@/lib/utils'

interface StatCardProps {
  label: string
  value: string | number
  sub?: string
  color?: string
  icon?: string
  trend?: 'up' | 'down' | 'neutral'
  urgent?: boolean
}

export function StatCard({ label, value, sub, color, icon, urgent }: StatCardProps) {
  return (
    <div className={cn(
      'mace-card p-5 flex flex-col gap-2 relative overflow-hidden',
      urgent && 'border-red-500/40 bg-red-500/5'
    )}>
      {urgent && (
        <div className="absolute top-0 right-0 w-1.5 h-full bg-red-500/60" />
      )}
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500 uppercase tracking-wider">{label}</span>
        {icon && <span className="text-lg">{icon}</span>}
      </div>
      <div className="font-mono font-bold text-3xl" style={{ color: color || '#e2e8f0' }}>
        {value}
      </div>
      {sub && <div className="text-xs text-slate-500">{sub}</div>}
    </div>
  )
}
