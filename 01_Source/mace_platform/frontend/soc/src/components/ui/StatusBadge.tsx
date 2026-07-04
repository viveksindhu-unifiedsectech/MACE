import { statusColor } from '@/lib/utils'
import { cn } from '@/lib/utils'

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border', statusColor(status))}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {status.replace('_', ' ')}
    </span>
  )
}
