import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminApi } from '@/lib/api'
import { Modal, FormField, Spinner } from '@/components/ui'
import { jurisdictionLabel, planLabel, fmtDate } from '@/lib/utils'
import type { TenantInfo } from '@/types'

const WEIGHT_PROFILES = ['usa_fedramp','india_cii','eu_gdpr','canada_pipeda','uae_nesa']
const JURISDICTIONS = ['US','IN','EU','CA','AE']
const SECTORS = ['Banking','Defence','Healthcare','Government','Energy','Telecom','Manufacturing','Retail','Technology','default']

export function TenantConfig() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState<Record<string, unknown>>({})

  const { data: tenant, isLoading } = useQuery<TenantInfo>({
    queryKey: ['tenant'],
    queryFn: () => adminApi.tenant().then(r => r.data)
  })

  const update = useMutation({
    mutationFn: (params: Record<string,unknown>) => adminApi.updateConfig(params),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['tenant'] }); setEditing(false) }
  })

  if (isLoading) return <div className="flex justify-center py-16"><Spinner /></div>
  if (!tenant) return null

  const openEdit = () => {
    setForm({
      jurisdiction: tenant.jurisdiction,
      weight_profile: tenant.weight_profile,
      sector: tenant.sector,
      cdcs_alert_threshold: tenant.cdcs_alert_threshold,
      rea_cdcs_threshold: tenant.rea_cdcs_threshold,
    })
    setEditing(true)
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Identity card */}
      <div className="adm-card p-6">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h2 className="text-xl font-bold text-white">{tenant.name}</h2>
            <div className="text-adm-muted text-sm font-mono mt-1">/{tenant.slug}</div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-sm bg-indigo-500/10 text-indigo-400 border border-indigo-500/25 px-3 py-1 rounded-full font-medium">
              {planLabel(tenant.plan)}
            </span>
            <button className="adm-btn-primary" onClick={openEdit}>Edit Config</button>
          </div>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            ['Jurisdiction', jurisdictionLabel(tenant.jurisdiction)],
            ['Weight Profile', tenant.weight_profile],
            ['Sector', tenant.sector || 'default'],
            ['Data Residency', tenant.data_residency],
          ].map(([k, v]) => (
            <div key={k} className="bg-adm-bg rounded-lg p-3 border border-adm-border">
              <div className="text-xs text-adm-muted mb-1">{k}</div>
              <div className="text-sm font-mono text-white">{v}</div>
            </div>
          ))}
        </div>
      </div>

      {/* MACE Engine Config */}
      <div className="adm-card p-6">
        <h3 className="font-semibold text-white mb-4">MACE Engine Configuration</h3>
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            ['CDCS Alert Threshold', tenant.cdcs_alert_threshold.toFixed(1), '#6366f1'],
            ['UREA REA Threshold', tenant.rea_cdcs_threshold.toFixed(1), '#8b5cf6'],
            ['Asset Limit', tenant.asset_limit.toLocaleString(), '#06b6d4'],
          ].map(([k, v, c]) => (
            <div key={k} className="bg-adm-bg rounded-lg p-4 border border-adm-border">
              <div className="text-xs text-adm-muted mb-1">{k}</div>
              <div className="text-2xl font-mono font-bold" style={{ color: c as string }}>{v}</div>
            </div>
          ))}
        </div>
        <div className="mt-4 grid grid-cols-3 gap-3">
          {[
            ['FedRAMP / GovCloud', tenant.is_fedramp],
            ['HIPAA BAA Signed', tenant.is_hipaa_baa],
            ['SOC 2 Compliant', tenant.soc2_compliant],
          ].map(([k, v]) => (
            <div key={k as string} className={`p-3 rounded-lg border text-sm flex items-center gap-2 ${v ? 'bg-green-500/10 border-green-500/25 text-green-400' : 'bg-adm-bg border-adm-border text-adm-muted'}`}>
              <span>{v ? '✓' : '○'}</span><span className="text-xs">{k as string}</span>
            </div>
          ))}
        </div>
      </div>

      {/* MACE Engine Stats */}
      {tenant.mace_stats && Object.keys(tenant.mace_stats).length > 0 && (
        <div className="adm-card p-6">
          <h3 className="font-semibold text-white mb-4">Live Engine Stats</h3>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {Object.entries(tenant.mace_stats).slice(0, 8).map(([k, v]) => (
              <div key={k} className="bg-adm-bg rounded-lg p-3 border border-adm-border">
                <div className="text-xs text-adm-muted mb-1">{k.replace(/_/g,' ')}</div>
                <div className="text-sm font-mono text-white">{typeof v === 'number' ? (v % 1 ? v.toFixed(3) : v) : String(v)}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Edit modal */}
      {editing && (
        <Modal title="Edit Tenant Configuration" onClose={() => setEditing(false)} width="max-w-xl">
          <div className="space-y-4">
            <div className="bg-amber-500/10 border border-amber-500/25 rounded-lg p-3 text-xs text-amber-400">
              ⚠ Changing jurisdiction or weight profile will reset the MACE engine — all cached correlation weights will be recalculated.
            </div>
            <FormField label="Jurisdiction">
              <select className="adm-input" value={form.jurisdiction as string} onChange={e => setForm({...form, jurisdiction: e.target.value})}>
                {JURISDICTIONS.map(j => <option key={j} value={j}>{jurisdictionLabel(j)}</option>)}
              </select>
            </FormField>
            <FormField label="Weight Profile">
              <select className="adm-input" value={form.weight_profile as string} onChange={e => setForm({...form, weight_profile: e.target.value})}>
                {WEIGHT_PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </FormField>
            <FormField label="Sector">
              <select className="adm-input" value={form.sector as string} onChange={e => setForm({...form, sector: e.target.value})}>
                {SECTORS.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </FormField>
            <div className="grid grid-cols-2 gap-4">
              <FormField label="CDCS Alert Threshold (0–10)">
                <input type="number" min={0} max={10} step={0.1} className="adm-input"
                  value={form.cdcs_alert_threshold as number}
                  onChange={e => setForm({...form, cdcs_alert_threshold: parseFloat(e.target.value)})} />
              </FormField>
              <FormField label="UREA Threshold (0–10)">
                <input type="number" min={0} max={10} step={0.1} className="adm-input"
                  value={form.rea_cdcs_threshold as number}
                  onChange={e => setForm({...form, rea_cdcs_threshold: parseFloat(e.target.value)})} />
              </FormField>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button className="adm-btn-ghost" onClick={() => setEditing(false)}>Cancel</button>
              <button className="adm-btn-primary" onClick={() => update.mutate(form)} disabled={update.isPending}>
                {update.isPending ? <Spinner size={14} /> : 'Save Changes'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
