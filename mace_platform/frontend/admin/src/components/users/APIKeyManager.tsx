import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminApi } from '@/lib/api'
import { Modal, FormField, Spinner, Table, Tr, Td, SectionHeader } from '@/components/ui'
import { fmtAgo } from '@/lib/utils'
import type { APIKey } from '@/types'

const SCOPES = ['assets:read','assets:write','events:write','incidents:read','incidents:write','admin:read']

export function APIKeyManager() {
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [newKey, setNewKey] = useState<string|null>(null)
  const [form, setForm] = useState({ name:'', scopes:['assets:write','events:write'] as string[] })

  const { data, isLoading } = useQuery<{keys:APIKey[]}>({
    queryKey: ['api-keys'],
    queryFn: () => adminApi.apiKeys().then(r => r.data)
  })

  const create = useMutation({
    mutationFn: () => adminApi.createApiKey(form.name, form.scopes),
    onSuccess: (r) => {
      qc.invalidateQueries({queryKey:['api-keys']})
      setCreating(false)
      setNewKey(r.data.key)
      setForm({ name:'', scopes:['assets:write','events:write'] })
    }
  })

  const revoke = useMutation({
    mutationFn: (id: string) => adminApi.revokeApiKey(id),
    onSuccess: () => qc.invalidateQueries({queryKey:['api-keys']})
  })

  const toggleScope = (s: string) => setForm(f => ({
    ...f, scopes: f.scopes.includes(s) ? f.scopes.filter(x=>x!==s) : [...f.scopes, s]
  }))

  return (
    <div className="animate-fade-in">
      <SectionHeader title="API Keys" action={<button className="adm-btn-primary" onClick={() => setCreating(true)}>+ New Key</button>} />

      {isLoading ? <div className="flex justify-center py-12"><Spinner /></div> : (
        <Table headers={['Name','Prefix','Scopes','Last Used','Status','']}>
          {data?.keys.map(k => (
            <Tr key={k.id}>
              <Td><span className="text-sm text-white font-medium">{k.name}</span></Td>
              <Td><code className="text-xs text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded">{k.prefix}…</code></Td>
              <Td>
                <div className="flex flex-wrap gap-1">
                  {k.scopes.slice(0,3).map(s => <span key={s} className="text-xs text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 rounded font-mono">{s}</span>)}
                  {k.scopes.length > 3 && <span className="text-xs text-adm-muted">+{k.scopes.length-3}</span>}
                </div>
              </Td>
              <Td><span className="text-xs text-adm-muted">{fmtAgo(k.last_used_at)}</span></Td>
              <Td>
                <span className={`text-xs px-2 py-0.5 rounded border font-mono ${k.is_active ? 'text-green-400 bg-green-500/10 border-green-500/25' : 'text-red-400 bg-red-500/10 border-red-500/25'}`}>
                  {k.is_active ? 'Active' : 'Revoked'}
                </span>
              </Td>
              <Td>
                {k.is_active && (
                  <button className="text-xs text-red-400 hover:text-red-300" onClick={() => { if(confirm(`Revoke "${k.name}"?`)) revoke.mutate(k.id) }}>
                    Revoke
                  </button>
                )}
              </Td>
            </Tr>
          ))}
        </Table>
      )}

      {/* Create key */}
      {creating && (
        <Modal title="Create API Key" onClose={() => setCreating(false)}>
          <div className="space-y-4">
            <FormField label="Key Name">
              <input className="adm-input" value={form.name} onChange={e => setForm({...form,name:e.target.value})} placeholder="CrowdStrike Connector" />
            </FormField>
            <FormField label="Scopes">
              <div className="grid grid-cols-2 gap-2">
                {SCOPES.map(s => (
                  <label key={s} className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={form.scopes.includes(s)} onChange={() => toggleScope(s)}
                      className="w-3.5 h-3.5 rounded border-adm-border bg-adm-bg text-indigo-500" />
                    <span className="text-xs font-mono text-adm-text">{s}</span>
                  </label>
                ))}
              </div>
            </FormField>
            <div className="flex justify-end gap-3 pt-2">
              <button className="adm-btn-ghost" onClick={() => setCreating(false)}>Cancel</button>
              <button className="adm-btn-primary" onClick={() => create.mutate()} disabled={!form.name || !form.scopes.length || create.isPending}>
                {create.isPending ? <Spinner size={14}/> : 'Generate Key'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Show new key ONCE */}
      {newKey && (
        <Modal title="⚠ Save Your API Key" onClose={() => setNewKey(null)}>
          <div className="space-y-4">
            <p className="text-sm text-amber-400">This key will NOT be shown again. Copy it now and store securely.</p>
            <div className="bg-adm-bg border border-adm-border rounded-lg p-4">
              <code className="text-xs text-green-400 break-all font-mono leading-relaxed">{newKey}</code>
            </div>
            <button className="adm-btn-primary w-full" onClick={() => { navigator.clipboard.writeText(newKey); setNewKey(null) }}>
              📋 Copy & Close
            </button>
          </div>
        </Modal>
      )}
    </div>
  )
}
