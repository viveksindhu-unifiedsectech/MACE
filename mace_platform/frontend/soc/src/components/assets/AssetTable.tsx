import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { assetsApi } from '@/lib/api'
import { ACSIndicator } from '@/components/ui/ACSIndicator'
import { SeverityBadge } from '@/components/ui/Badge'
import { CDCSMeter } from '@/components/ui/CDCSMeter'
import { Spinner } from '@/components/ui/Spinner'
import { assetClassIcon, fmtAgo, truncate } from '@/lib/utils'
import { cn } from '@/lib/utils'
import type { Asset, AssetClass, AssetStatus } from '@/types'

interface AssetTableProps {
  onSelect?: (asset: Asset) => void
}

export function AssetTable({ onSelect }: AssetTableProps) {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [filterClass, setFilterClass] = useState<AssetClass | ''>('')
  const [filterStatus, setFilterStatus] = useState<AssetStatus | ''>('')
  const [filterShadowIt, setFilterShadowIt] = useState(false)
  const [filterGeo, setFilterGeo] = useState(false)
  const [sortBy, setSortBy] = useState('last_seen_at')
  const [order, setOrder] = useState<'asc' | 'desc'>('desc')

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['assets', page, search, filterClass, filterStatus, filterShadowIt, filterGeo, sortBy, order],
    queryFn: () => assetsApi.list({
      page,
      page_size: 50,
      ...(search && { search }),
      ...(filterClass && { asset_class: filterClass }),
      ...(filterStatus && { status: filterStatus }),
      ...(filterShadowIt && { shadow_it: true }),
      ...(filterGeo && { geo_anomaly: true }),
      sort_by: sortBy,
      order,
    }).then(r => r.data),
    placeholderData: (prev) => prev,
  })

  const classes: AssetClass[] = ['cloud_vm','container','kubernetes_node','serverless','endpoint','server','mobile','network_device','ot_ics','iot_device','database']

  return (
    <div className="flex flex-col gap-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <input
          value={search} onChange={e => { setSearch(e.target.value); setPage(1) }}
          placeholder="Search hostname, IP, owner..."
          className="bg-mace-card border border-mace-border rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 w-64 focus:outline-none focus:border-cyan-500/50"
        />
        <select
          value={filterClass}
          onChange={e => { setFilterClass(e.target.value as AssetClass | ''); setPage(1) }}
          className="bg-mace-card border border-mace-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500/50"
        >
          <option value="">All Classes</option>
          {classes.map(c => <option key={c} value={c}>{assetClassIcon(c)} {c.replace('_', ' ')}</option>)}
        </select>
        <select
          value={filterStatus}
          onChange={e => { setFilterStatus(e.target.value as AssetStatus | ''); setPage(1) }}
          className="bg-mace-card border border-mace-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500/50"
        >
          <option value="">All Status</option>
          <option value="active">Active</option>
          <option value="stale">Stale</option>
          <option value="shadow_it">Shadow IT</option>
          <option value="geo_anomaly">Geo Anomaly</option>
        </select>
        <button
          onClick={() => { setFilterShadowIt(!filterShadowIt); setPage(1) }}
          className={cn('px-3 py-2 rounded-lg text-sm border transition-colors',
            filterShadowIt ? 'bg-orange-500/20 border-orange-500/40 text-orange-400' : 'bg-mace-card border-mace-border text-slate-400 hover:text-white'
          )}
        >◌ Shadow IT</button>
        <button
          onClick={() => { setFilterGeo(!filterGeo); setPage(1) }}
          className={cn('px-3 py-2 rounded-lg text-sm border transition-colors',
            filterGeo ? 'bg-red-500/20 border-red-500/40 text-red-400' : 'bg-mace-card border-mace-border text-slate-400 hover:text-white'
          )}
        >⚡ Geo Anomaly</button>

        {isFetching && <div className="flex items-center"><Spinner size={16} /></div>}
        {data && (
          <div className="ml-auto text-sm text-slate-500 self-center">
            {data.total.toLocaleString()} assets
          </div>
        )}
      </div>

      {/* Table */}
      <div className="mace-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-mace-border">
                {[
                  { key: 'hostname', label: 'Asset' },
                  { key: null, label: 'Class' },
                  { key: 'acs_score', label: 'ACS' },
                  { key: 'cdcs_score', label: 'CDCS' },
                  { key: null, label: 'Risk' },
                  { key: null, label: 'Vulns' },
                  { key: null, label: 'Sources' },
                  { key: 'last_seen_at', label: 'Last Seen' },
                ].map(col => (
                  <th
                    key={col.label}
                    className={cn(
                      'px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider',
                      col.key && 'cursor-pointer hover:text-white select-none'
                    )}
                    onClick={() => {
                      if (!col.key) return
                      if (sortBy === col.key) setOrder(o => o === 'asc' ? 'desc' : 'asc')
                      else { setSortBy(col.key); setOrder('desc') }
                    }}
                  >
                    {col.label}
                    {col.key === sortBy && <span className="ml-1">{order === 'asc' ? '↑' : '↓'}</span>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={8} className="text-center py-16"><Spinner /></td></tr>
              ) : data?.items.length === 0 ? (
                <tr><td colSpan={8} className="text-center py-16 text-slate-500">No assets found</td></tr>
              ) : (
                data?.items.map(asset => (
                  <AssetRow key={asset.id} asset={asset} onSelect={onSelect} />
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data && data.total > 50 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-mace-border">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 rounded text-sm text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
            >
              ← Prev
            </button>
            <span className="text-xs text-slate-500">
              Page {page} · {data.total} total
            </span>
            <button
              onClick={() => setPage(p => p + 1)}
              disabled={!data.has_next}
              className="px-3 py-1 rounded text-sm text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
            >
              Next →
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function AssetRow({ asset, onSelect }: { asset: Asset; onSelect?: (a: Asset) => void }) {
  return (
    <tr
      className="border-b border-mace-border hover:bg-slate-800/40 transition-colors cursor-pointer animate-fade-in"
      onClick={() => onSelect?.(asset)}
    >
      {/* Asset identity */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          {asset.shadow_it_flag && <span className="text-orange-400" title="Shadow IT">◌</span>}
          {asset.geo_velocity_flag && <span className="text-red-400" title="Geo Anomaly">⚡</span>}
          {asset.is_critical_infra && <span className="text-amber-400" title="Critical Infrastructure">★</span>}
          <div>
            <div className="font-mono text-white text-xs">{truncate(asset.hostname || asset.ip_address, 28)}</div>
            <div className="text-slate-500 text-xs">{asset.ip_address} · {asset.canonical_id.slice(0,8)}</div>
          </div>
        </div>
      </td>
      <td className="px-4 py-3">
        <span className="text-lg" title={asset.asset_class}>{assetClassIcon(asset.asset_class)}</span>
      </td>
      <td className="px-4 py-3">
        <ACSIndicator score={asset.acs_score} />
      </td>
      <td className="px-4 py-3 min-w-[120px]">
        {asset.cdcs_score != null
          ? <CDCSMeter score={asset.cdcs_score} size="sm" />
          : <span className="text-slate-600 text-xs">—</span>
        }
      </td>
      <td className="px-4 py-3">
        {asset.risk_level
          ? <SeverityBadge severity={asset.risk_level} />
          : <span className="text-slate-600 text-xs">—</span>
        }
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-1.5">
          {asset.critical_vuln_count > 0 && (
            <span className="bg-red-500/10 text-red-400 text-xs px-1.5 py-0.5 rounded border border-red-500/20 font-mono">
              {asset.critical_vuln_count}C
            </span>
          )}
          {asset.high_vuln_count > 0 && (
            <span className="bg-orange-500/10 text-orange-400 text-xs px-1.5 py-0.5 rounded border border-orange-500/20 font-mono">
              {asset.high_vuln_count}H
            </span>
          )}
          {asset.critical_vuln_count === 0 && asset.high_vuln_count === 0 && (
            <span className="text-slate-600 text-xs">—</span>
          )}
        </div>
      </td>
      <td className="px-4 py-3">
        <div className="flex gap-1">
          {asset.source_set.slice(0, 3).map(s => (
            <span key={s} className="text-xs bg-slate-800 border border-slate-700 px-1.5 py-0.5 rounded text-slate-400">
              {s.slice(0, 2).toUpperCase()}
            </span>
          ))}
          {asset.source_set.length > 3 && (
            <span className="text-xs text-slate-500">+{asset.source_set.length - 3}</span>
          )}
        </div>
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-slate-500">{fmtAgo(asset.last_seen_at)}</span>
      </td>
    </tr>
  )
}
