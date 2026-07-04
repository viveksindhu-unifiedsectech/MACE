import { clsx, type ClassValue } from 'clsx'
import { format, parseISO, formatDistanceToNow } from 'date-fns'
export const cn = (...a: ClassValue[]) => clsx(a)
export const fmtDate = (s: string) => { try { return format(parseISO(s), 'dd MMM yyyy HH:mm') } catch { return '—' } }
export const fmtAgo = (s: string | null) => { if (!s) return 'Never'; try { return formatDistanceToNow(parseISO(s), { addSuffix: true }) } catch { return '—' } }
export const roleColor = (r: string) => ({ super_admin: 'text-purple-400 bg-purple-500/10 border-purple-500/25', tenant_admin: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/25', soc_analyst: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/25', read_only: 'text-slate-400 bg-slate-500/10 border-slate-500/25', api_user: 'text-amber-400 bg-amber-500/10 border-amber-500/25' }[r] || 'text-slate-400 bg-slate-500/10 border-slate-500/25')
export const connectorStatusColor = (s: string) => ({ active: 'text-green-400 bg-green-500/10 border-green-500/25', inactive: 'text-slate-400 bg-slate-500/10 border-slate-500/25', error: 'text-red-400 bg-red-500/10 border-red-500/25', testing: 'text-amber-400 bg-amber-500/10 border-amber-500/25' }[s] || 'text-slate-400')
export const jurisdictionLabel = (j: string) => ({ US: '🇺🇸 USA', IN: '🇮🇳 India', EU: '🇪🇺 Europe', CA: '🇨🇦 Canada', AE: '🇦🇪 UAE' }[j] || j)
export const planLabel = (p: string) => ({ msme: '🏢 MSME', starter: '⭐ Starter', professional: '💎 Professional', enterprise: '🏛 Enterprise' }[p] || p)
export const connectorIcon = (t: string) => ({ crowdstrike: '🦅', tenable: '🔍', axonius: '◈', qualys: '🛡', splunk: '📊', sentinel_one: '🛡', misp: '🕵', virustotal: '🔬', recorded_future: '🔮', custom_api: '⚙' }[t] || '🔌')
export const fmtHours = (h: number) => {
  if (h < 0) return `${Math.abs(Math.round(h))}h overdue`
  if (h < 1) return `${Math.round(h * 60)}min`
  if (h < 24) return `${Math.round(h)}h`
  return `${Math.round(h / 24)}d`
}
