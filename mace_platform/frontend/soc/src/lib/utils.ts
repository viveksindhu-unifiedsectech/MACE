import { clsx, type ClassValue } from 'clsx'
import { formatDistanceToNow, format, parseISO } from 'date-fns'

export function cn(...inputs: ClassValue[]) { return clsx(inputs) }

export function severityColor(sev: string) {
  switch (sev?.toLowerCase()) {
    case 'critical': return 'text-red-400'
    case 'high':     return 'text-orange-400'
    case 'medium':   return 'text-amber-400'
    case 'low':      return 'text-green-400'
    default:         return 'text-slate-400'
  }
}

export function severityBg(sev: string) {
  switch (sev?.toLowerCase()) {
    case 'critical': return 'bg-red-500/10 text-red-400 border-red-500/20'
    case 'high':     return 'bg-orange-500/10 text-orange-400 border-orange-500/20'
    case 'medium':   return 'bg-amber-500/10 text-amber-400 border-amber-500/20'
    case 'low':      return 'bg-green-500/10 text-green-400 border-green-500/20'
    default:         return 'bg-slate-500/10 text-slate-400 border-slate-500/20'
  }
}

export function cdcsColor(score: number) {
  if (score >= 8.5) return '#ff4d4f'
  if (score >= 7.0) return '#fa8c16'
  if (score >= 5.0) return '#faad14'
  return '#52c41a'
}

export function acsColor(score: number) {
  if (score >= 0.8) return '#52c41a'
  if (score >= 0.5) return '#faad14'
  if (score >= 0.3) return '#fa8c16'
  return '#ff4d4f'
}

export function statusColor(status: string) {
  switch (status) {
    case 'open':          return 'bg-red-500/10 text-red-400 border-red-500/20'
    case 'investigating': return 'bg-orange-500/10 text-orange-400 border-orange-500/20'
    case 'contained':     return 'bg-amber-500/10 text-amber-400 border-amber-500/20'
    case 'eradicated':    return 'bg-teal-500/10 text-teal-400 border-teal-500/20'
    case 'recovered':     return 'bg-blue-500/10 text-blue-400 border-blue-500/20'
    case 'closed':        return 'bg-slate-500/10 text-slate-400 border-slate-500/20'
    case 'false_positive':return 'bg-purple-500/10 text-purple-400 border-purple-500/20'
    default:              return 'bg-slate-500/10 text-slate-400 border-slate-500/20'
  }
}

export function assetClassIcon(cls: string) {
  switch (cls) {
    case 'cloud_vm':        return '☁️'
    case 'container':       return '📦'
    case 'kubernetes_node': return '⚙️'
    case 'serverless':      return '⚡'
    case 'endpoint':        return '💻'
    case 'server':          return '🖥️'
    case 'mobile':          return '📱'
    case 'network_device':  return '🌐'
    case 'ot_ics':          return '🏭'
    case 'iot_device':      return '📡'
    case 'database':        return '🗄️'
    default:                return '❓'
  }
}

export function jurisdictionLabel(j: string) {
  switch (j) {
    case 'US': return '🇺🇸 USA'
    case 'IN': return '🇮🇳 India'
    case 'EU': return '🇪🇺 Europe'
    case 'CA': return '🇨🇦 Canada'
    case 'AE': return '🇦🇪 UAE'
    default:   return j
  }
}

export function fmtTime(iso: string) {
  try { return format(parseISO(iso), 'HH:mm:ss') } catch { return '—' }
}

export function fmtDate(iso: string) {
  try { return format(parseISO(iso), 'dd MMM yyyy HH:mm') } catch { return '—' }
}

export function fmtAgo(iso: string) {
  try { return formatDistanceToNow(parseISO(iso), { addSuffix: true }) } catch { return '—' }
}

export function fmtHours(h: number) {
  if (h < 0) return `${Math.abs(Math.round(h))}h overdue`
  if (h < 1) return `${Math.round(h * 60)}min`
  if (h < 24) return `${Math.round(h)}h`
  return `${Math.round(h / 24)}d`
}

export function truncate(s: string | null | undefined, n = 32) {
  if (!s) return '—'
  return s.length > n ? s.slice(0, n) + '…' : s
}
