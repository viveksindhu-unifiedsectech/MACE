import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { adminApi } from '@/lib/api'
import { Table, Tr, Td, Spinner, SectionHeader } from '@/components/ui'
import { fmtDate } from '@/lib/utils'
import type { AuditEntry } from '@/types'

const ACTION_COLOR = (a: string) => {
  if (a.includes('login')) return 'text-green-400'
  if (a.includes('delete') || a.includes('revoke')) return 'text-red-400'
  if (a.includes('create')) return 'text-indigo-400'
  if (a.includes('update') || a.includes('config')) return 'text-amber-400'
  return 'text-adm-muted'
}

export function AuditLogViewer() {
  const [page, setPage] = useState(1)
  const [actionFilter, setActionFilter] = useState('')

  const { data, isLoading } = useQuery<{logs:AuditEntry[]}>({
    queryKey: ['audit-log', page, actionFilter],
    queryFn: () => adminApi.auditLog({ page, page_size:100, ...(actionFilter && { action: actionFilter }) }).then(r => r.data)
  })

  return (
    <div className="animate-fade-in">
      <SectionHeader title="Audit Log" action={
        <div className="flex items-center gap-2">
          <input value={actionFilter} onChange={e => { setActionFilter(e.target.value); setPage(1) }}
            placeholder="Filter by action..." className="adm-input w-48 text-xs" />
          <div className="text-xs text-adm-muted bg-adm-card border border-adm-border px-3 py-2 rounded-lg">
            Immutable · SOC2 · FedRAMP · GDPR
          </div>
        </div>
      }/>
      <div className="adm-card p-3 mb-4 text-xs text-adm-muted">
        All platform actions are immutably recorded. Audit logs cannot be modified or deleted. Retained per jurisdictional requirements (US: 7yr, EU: 5yr, IN: 5yr, UAE: 5yr).
      </div>

      {isLoading ? <div className="flex justify-center py-12"><Spinner /></div> : (
        <Table headers={['Timestamp','User','Action','Resource','IP','Status']}>
          {data?.logs.map(entry => (
            <Tr key={entry.id}>
              <Td><span className="text-xs font-mono text-adm-muted">{fmtDate(entry.created_at)}</span></Td>
              <Td><span className="text-xs text-adm-text truncate max-w-[160px] block">{entry.user_email || '(system)'}</span></Td>
              <Td><span className={`text-xs font-mono ${ACTION_COLOR(entry.action)}`}>{entry.action}</span></Td>
              <Td>
                {entry.resource_type && (
                  <span className="text-xs text-adm-muted">
                    {entry.resource_type}
                    {entry.resource_id && <span className="font-mono ml-1 text-adm-text/60">{entry.resource_id.slice(0,8)}</span>}
                  </span>
                )}
              </Td>
              <Td><span className="text-xs font-mono text-adm-muted">{entry.ip_address || '—'}</span></Td>
              <Td>
                <span className={`text-xs ${entry.success ? 'text-green-400' : 'text-red-400'}`}>
                  {entry.success ? '✓' : '✗'}
                </span>
              </Td>
            </Tr>
          ))}
        </Table>
      )}

      {(data?.logs.length || 0) >= 100 && (
        <div className="flex justify-center gap-3 mt-4">
          <button onClick={() => setPage(p => Math.max(1,p-1))} disabled={page===1} className="adm-btn-ghost text-xs px-3 py-1.5 disabled:opacity-30">← Prev</button>
          <span className="text-xs text-adm-muted self-center">Page {page}</span>
          <button onClick={() => setPage(p => p+1)} className="adm-btn-ghost text-xs px-3 py-1.5">Next →</button>
        </div>
      )}
    </div>
  )
}
