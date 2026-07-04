import { cn } from '@/lib/utils'

interface BadgeProps {
  children: React.ReactNode
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'ghost'
  className?: string
}

export function Badge({ children, variant = 'ghost', className }: BadgeProps) {
  const variants = {
    critical: 'bg-red-500/10 text-red-400 border border-red-500/25',
    high:     'bg-orange-500/10 text-orange-400 border border-orange-500/25',
    medium:   'bg-amber-500/10 text-amber-400 border border-amber-500/25',
    low:      'bg-green-500/10 text-green-400 border border-green-500/25',
    info:     'bg-cyan-500/10 text-cyan-400 border border-cyan-500/25',
    ghost:    'bg-slate-500/10 text-slate-400 border border-slate-500/25',
  }
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium font-mono', variants[variant], className)}>
      {children}
    </span>
  )
}

export function SeverityBadge({ severity }: { severity: string }) {
  const v = severity?.toLowerCase() as 'critical' | 'high' | 'medium' | 'low'
  return <Badge variant={v}>{severity?.toUpperCase()}</Badge>
}
