import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminApi } from '@/lib/api'
import { Modal, FormField, Spinner, SectionHeader } from '@/components/ui'
import { connectorStatusColor, connectorIcon, fmtAgo } from '@/lib/utils'
import type { Connector } from '@/types'

const CONNECTOR_TYPES = [
  { type:'crowdstrike', label:'CrowdStrike Falcon', desc:'Endpoint detection + asset inventory' },
  { type:'tenable', label:'Tenable.io', desc:'Vulnerability scanning + asset discovery' },
  { type:'axonius', label:'Axonius', desc:'Asset intelligence platform' },
  { type:'qualys', label:'Qualys VMDR', desc:'Vulnerability + compliance scanning' },
  { type:'splunk', label:'Splunk SIEM', desc:'Security events + log management' },
  { type:'sentinel_one', label:'SentinelOne', desc:'AI-powered endpoint protection' },
  { type:'misp', label:'MISP', desc:'Threat intelligence sharing platform' },
  { type:'virustotal', label:'VirusTotal', desc:'Malware / IOC intelligence' },
  { type:'recorded_future', label:'Recorded Future', desc:'Threat intelligence platform' },
  { type:'custom_api', label:'Custom API', desc:'Generic REST API connector' },
]

export function ConnectorManager() {
  const qc = useQueryClient()
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({
    connector_type:'crowdstrike', name:'', base_url:'', client_id:'',
    client_secret:'', api_key_value:'', sync_interval_minutes:60
  })

  const { data, isLoading } = useQuery<{connectors:Connector[]}>({
    queryKey:['connectors'],
    queryFn: () => adminApi.connectors().then(r => r.data)
  })

  const create = useMutation({
    mutationFn: () => adminApi.createConnector(form as Record<string,unknown>),
    onSuccess: () => { qc.invalidateQueries({queryKey:['connectors']}); setAdding(false) }
  })

  const del = useMutation({
    mutationFn: (id:string) => adminApi.deleteConnector(id),
    onSuccess: () => qc.invalidateQueries({queryKey:['connectors']})
  })

  return (
    <div className="animate-fade-in">
      <SectionHeader title="Data Connectors" action={
        <button className="adm-btn-primary" onClick={() => setAdding(true)}>+ Add Connector</button>
      }/>

      {isLoading ? <div className="flex justify-center py-12"><Spinner /></div> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Existing connectors */}
          {data?.connectors.map(c => <ConnectorCard key={c.id} connector={c} onDelete={() => { if(confirm(`Delete "${c.name}"?`)) del.mutate(c.id) }} />)}

          {/* Available not yet added */}
          {data?.connectors.length === 0 && (
            <div className="lg:col-span-2 adm-card p-8 text-center text-adm-muted text-sm">
              No connectors configured. Add your first data source.
            </div>
          )}
        </div>
      )}

      {/* Available connectors showcase */}
      <div className="mt-6">
        <h3 className="font-medium text-adm-text mb-3 text-sm">Available Integrations</h3>
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          {CONNECTOR_TYPES.map(ct => (
            <div key={ct.type} className="adm-card p-3 cursor-pointer hover:border-indigo-500/50 transition-colors" onClick={() => { setForm(f=>({...f,connector_type:ct.type,name:ct.label})); setAdding(true) }}>
              <div className="text-2xl mb-2">{connectorIcon(ct.type)}</div>
              <div className="text-xs font-medium text-white">{ct.label}</div>
              <div className="text-xs text-adm-muted mt-0.5">{ct.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Add connector modal */}
      {adding && (
        <Modal title="Add Data Connector" onClose={() => setAdding(false)} width="max-w-xl">
          <div className="space-y-4">
            <FormField label="Connector Type">
              <select className="adm-input" value={form.connector_type} onChange={e => {
                const ct = CONNECTOR_TYPES.find(c=>c.type===e.target.value)
                setForm({...form, connector_type:e.target.value, name:ct?.label||''})
              }}>
                {CONNECTOR_TYPES.map(ct => <option key={ct.type} value={ct.type}>{connectorIcon(ct.type)} {ct.label}</option>)}
              </select>
            </FormField>
            <FormField label="Display Name">
              <input className="adm-input" value={form.name} onChange={e => setForm({...form,name:e.target.value})} placeholder="Production CrowdStrike" />
            </FormField>
            <FormField label="Base URL (optional — leave blank for cloud)">
              <input className="adm-input" value={form.base_url} onChange={e => setForm({...form,base_url:e.target.value})} placeholder="https://api.crowdstrike.com" />
            </FormField>

            {/* Credential fields based on type */}
            {['crowdstrike','axonius','qualys'].includes(form.connector_type) && <>
              <FormField label="Client ID / Access Key">
                <input className="adm-input" value={form.client_id} onChange={e => setForm({...form,client_id:e.target.value})} placeholder="Client ID" />
              </FormField>
              <FormField label="Client Secret">
                <input type="password" className="adm-input" value={form.client_secret} onChange={e => setForm({...form,client_secret:e.target.value})} placeholder="Client Secret (stored encrypted)" />
              </FormField>
            </>}
            {['tenable','misp','virustotal','recorded_future','custom_api','splunk','sentinel_one'].includes(form.connector_type) && (
              <FormField label="API Key">
                <input type="password" className="adm-input" value={form.api_key_value} onChange={e => setForm({...form,api_key_value:e.target.value})} placeholder="API Key (stored encrypted)" />
              </FormField>
            )}

            <FormField label="Sync Interval (minutes)">
              <input type="number" min={15} max={1440} className="adm-input" value={form.sync_interval_minutes} onChange={e => setForm({...form,sync_interval_minutes:parseInt(e.target.value)})} />
            </FormField>

            <div className="bg-adm-surface border border-adm-border rounded-lg p-3 text-xs text-adm-muted">
              🔒 Credentials are stored encrypted using AES-256. In production, secrets are stored in AWS Secrets Manager or Azure Key Vault — never in plaintext.
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button className="adm-btn-ghost" onClick={() => setAdding(false)}>Cancel</button>
              <button className="adm-btn-primary" onClick={() => create.mutate()} disabled={!form.name || create.isPending}>
                {create.isPending ? <Spinner size={14}/> : 'Add Connector'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}

function ConnectorCard({ connector: c, onDelete }: { connector: Connector; onDelete: () => void }) {
  return (
    <div className="adm-card p-5 flex flex-col gap-3">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <span className="text-2xl">{connectorIcon(c.type)}</span>
          <div>
            <div className="text-sm font-medium text-white">{c.name}</div>
            <div className="text-xs text-adm-muted font-mono">{c.type}</div>
          </div>
        </div>
        <span className={`text-xs px-2 py-0.5 rounded border font-mono ${connectorStatusColor(c.status)}`}>{c.status}</span>
      </div>

      <div className="grid grid-cols-3 gap-2">
        {[
          ['Assets', c.provides_assets],
          ['Vulns', c.provides_vulns],
          ['Events', c.provides_events],
        ].map(([k, v]) => (
          <div key={k as string} className={`text-center text-xs py-1 rounded ${v ? 'text-green-400 bg-green-500/10' : 'text-adm-muted bg-adm-bg'}`}>
            {v ? '✓' : '○'} {k as string}
          </div>
        ))}
      </div>

      <div className="text-xs text-adm-muted space-y-1">
        <div className="flex justify-between">
          <span>Last sync</span>
          <span className="text-adm-text">{fmtAgo(c.last_sync_at)}</span>
        </div>
        <div className="flex justify-between">
          <span>Records synced</span>
          <span className="text-indigo-400 font-mono">{c.last_sync_count.toLocaleString()}</span>
        </div>
        <div className="flex justify-between">
          <span>Sync interval</span>
          <span className="text-adm-text">{c.sync_interval_minutes}m</span>
        </div>
      </div>

      {c.error_message && (
        <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded p-2">
          ⚠ {c.error_message}
        </div>
      )}

      <button className="adm-btn-danger text-xs py-1.5" onClick={onDelete}>Delete Connector</button>
    </div>
  )
}
