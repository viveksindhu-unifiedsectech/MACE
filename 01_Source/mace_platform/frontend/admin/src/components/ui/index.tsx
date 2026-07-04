import { cn } from '@/lib/utils'

export function Spinner({ size = 18 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" className="animate-spin text-indigo-400"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" fill="none"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
}

export function Badge({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border font-mono', className)}>{children}</span>
}

export function StatCard({ label, value, sub, color, icon }: { label: string; value: string|number; sub?: string; color?: string; icon?: string }) {
  return (
    <div className="adm-card p-5 flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-adm-muted uppercase tracking-wider">{label}</span>
        {icon && <span className="text-lg">{icon}</span>}
      </div>
      <div className="font-mono font-bold text-3xl" style={{ color: color || '#e2e8f0' }}>{value}</div>
      {sub && <div className="text-xs text-adm-muted">{sub}</div>}
    </div>
  )
}

interface ModalProps { title: string; onClose: () => void; children: React.ReactNode; width?: string }
export function Modal({ title, onClose, children, width = 'max-w-lg' }: ModalProps) {
  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className={cn('adm-card p-6 w-full animate-slide-up', width)} onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-5">
          <h2 className="font-semibold text-white text-base">{title}</h2>
          <button onClick={onClose} className="text-adm-muted hover:text-white text-xl leading-none">✕</button>
        </div>
        {children}
      </div>
    </div>
  )
}

export function Table({ headers, children, empty }: { headers: string[]; children: React.ReactNode; empty?: string }) {
  return (
    <div className="adm-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-adm-border">
              {headers.map(h => <th key={h} className="px-4 py-3 text-left text-xs font-medium text-adm-muted uppercase tracking-wider">{h}</th>)}
            </tr>
          </thead>
          <tbody>{children}</tbody>
        </table>
      </div>
      {!children && empty && <div className="text-center py-12 text-adm-muted text-sm">{empty}</div>}
    </div>
  )
}

export function Tr({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) {
  return <tr className={cn('border-b border-adm-border transition-colors', onClick && 'cursor-pointer hover:bg-adm-surface/50')} onClick={onClick}>{children}</tr>
}

export function Td({ children, className }: { children: React.ReactNode; className?: string }) {
  return <td className={cn('px-4 py-3', className)}>{children}</td>
}

export function SectionHeader({ title, action }: { title: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <h2 className="font-semibold text-white">{title}</h2>
      {action}
    </div>
  )
}

export function FormField({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><label className="adm-label">{label}</label>{children}</div>
}
