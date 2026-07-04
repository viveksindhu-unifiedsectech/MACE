import { useState } from 'react'
import { Layout } from '@/components/layout/Layout'
import { AssetTable } from '@/components/assets/AssetTable'
import { DonutScore } from '@/components/ui/CDCSMeter'
import { ACSIndicator } from '@/components/ui/ACSIndicator'
import { SeverityBadge } from '@/components/ui/Badge'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { fmtDate, assetClassIcon, truncate } from '@/lib/utils'
import type { Asset } from '@/types'

export default function Assets() {
  const [selected, setSelected] = useState<Asset | null>(null)

  return (
    <Layout title="Asset Inventory">
      <AssetTable onSelect={setSelected} />

      {/* Asset detail drawer */}
      {selected && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-end" onClick={() => setSelected(null)}>
          <div
            className="h-full w-full max-w-lg bg-mace-surface border-l border-mace-border overflow-y-auto animate-slide-in p-6 space-y-5"
            onClick={e => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xl">{assetClassIcon(selected.asset_class)}</span>
                  <span className="text-xs text-slate-500 font-mono">{selected.asset_class.replace('_', ' ')}</span>
                  {selected.shadow_it_flag && <span className="text-xs text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded">Shadow IT</span>}
                  {selected.is_critical_infra && <span className="text-xs text-amber-400 border border-amber-500/20 px-1.5 py-0.5 rounded">Critical</span>}
                </div>
                <h2 className="text-white font-semibold">{selected.hostname || selected.ip_address || selected.canonical_id.slice(0,16)}</h2>
                <div className="font-mono text-xs text-slate-500 mt-1">{selected.canonical_id}</div>
              </div>
              <div className="flex items-center gap-3">
                {selected.cdcs_score && <DonutScore score={selected.cdcs_score} label="CDCS" size={56} />}
                <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-white text-xl">✕</button>
              </div>
            </div>

            {/* Scores */}
            <div className="grid grid-cols-2 gap-3">
              <div className="mace-card p-3">
                <div className="text-xs text-slate-500 mb-2">Asset Confidence Score</div>
                <ACSIndicator score={selected.acs_score} />
                <div className="text-xs text-slate-500 mt-1">{selected.quorum_sources} source{selected.quorum_sources !== 1 ? 's' : ''}</div>
              </div>
              <div className="mace-card p-3">
                <div className="text-xs text-slate-500 mb-2">Risk Level</div>
                {selected.risk_level ? <SeverityBadge severity={selected.risk_level} /> : <span className="text-slate-600 text-xs">No risk scored</span>}
              </div>
            </div>

            {/* Identity */}
            <div className="mace-card p-4 space-y-2">
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">Identity</div>
              {[
                ['Hostname', selected.hostname],
                ['IP Address', selected.ip_address],
                ['MAC Address', selected.mac_address],
                ['OS', selected.os],
                ['Cloud Instance', selected.cloud_instance_id],
                ['Owner', selected.owner],
                ['Sector', selected.sector],
                ['Jurisdiction', selected.jurisdiction],
                ['Classification', selected.data_classification],
              ].map(([k, v]) => v && (
                <div key={k} className="flex justify-between py-1 border-b border-mace-border last:border-0">
                  <span className="text-xs text-slate-500">{k}</span>
                  <span className="text-xs font-mono text-white">{v}</span>
                </div>
              ))}
            </div>

            {/* CVEs */}
            {selected.open_cves.length > 0 && (
              <div className="mace-card p-4">
                <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">
                  Open CVEs ({selected.open_cves.length})
                </div>
                <div className="flex flex-wrap gap-2">
                  {selected.open_cves.slice(0, 12).map(cve => (
                    <span key={cve} className="font-mono text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded">
                      {cve}
                    </span>
                  ))}
                  {selected.open_cves.length > 12 && (
                    <span className="text-xs text-slate-500">+{selected.open_cves.length - 12} more</span>
                  )}
                </div>
              </div>
            )}

            {/* Sources */}
            <div className="mace-card p-4">
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">Data Sources</div>
              <div className="flex gap-2">
                {selected.source_set.map(s => (
                  <span key={s} className="text-sm bg-slate-800 border border-slate-700 px-3 py-1 rounded text-slate-300 font-mono">
                    {s}
                  </span>
                ))}
              </div>
            </div>

            {/* Timeline */}
            <div className="mace-card p-4 space-y-1">
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">Timeline</div>
              <div className="flex justify-between py-1">
                <span className="text-xs text-slate-500">First Seen</span>
                <span className="text-xs text-slate-300">{fmtDate(selected.first_seen_at)}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-xs text-slate-500">Last Seen</span>
                <span className="text-xs text-slate-300">{fmtDate(selected.last_seen_at)}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </Layout>
  )
}
