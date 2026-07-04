import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { incidentsApi } from '@/lib/api'
import { CDCSBreakdownChart } from '@/components/dashboard/CDCSBreakdownChart'
import { DonutScore } from '@/components/ui/CDCSMeter'
import { SeverityBadge } from '@/components/ui/Badge'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { Spinner } from '@/components/ui/Spinner'
import { fmtDate, fmtAgo } from '@/lib/utils'
import type { Incident } from '@/types'

interface IncidentDetailProps {
  incident: Incident
  onClose: () => void
}

export function IncidentDetail({ incident, onClose }: IncidentDetailProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'feedback'>('overview')
  const [newStatus, setNewStatus] = useState(incident.status)
  const [assignEmail, setAssignEmail] = useState(incident.assigned_to || '')
  const [notes, setNotes] = useState('')
  const [downloadingDraft, setDownloadingDraft] = useState<string | null>(null)
  const qc = useQueryClient()

  const { data: evidence, isLoading: evidenceLoading } = useQuery({
    queryKey: ['evidence', incident.id],
    queryFn: () => incidentsApi.getEvidence(incident.id).then(r => r.data),
    enabled: activeTab === 'evidence' && incident.has_evidence,
  })

  const updateStatus = useMutation({
    mutationFn: () => incidentsApi.updateStatus(incident.id, newStatus, notes || undefined),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incidents'] }),
  })

  const assign = useMutation({
    mutationFn: () => incidentsApi.assign(incident.id, assignEmail),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incidents'] }),
  })

  const feedback = useMutation({
    mutationFn: (confirmed: boolean) => incidentsApi.submitFeedback(incident.id, confirmed, notes || undefined),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incidents'] }),
  })

  const downloadDraft = async (framework: string) => {
    setDownloadingDraft(framework)
    try {
      const { data } = await incidentsApi.downloadDraft(incident.id, framework)
      const blob = new Blob([data], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = `${incident.incident_ref}_${framework}.txt`; a.click()
      URL.revokeObjectURL(url)
    } finally {
      setDownloadingDraft(null)
    }
  }

  const tabs = ['overview', 'evidence', 'feedback'] as const

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-end" onClick={onClose}>
      <div
        className="h-full w-full max-w-2xl bg-mace-surface border-l border-mace-border overflow-y-auto animate-slide-in"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 bg-mace-surface border-b border-mace-border p-6 z-10">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-cyan-400 font-bold">{incident.incident_ref}</span>
                <SeverityBadge severity={incident.severity} />
                <StatusBadge status={incident.status} />
              </div>
              <h2 className="text-white font-semibold text-sm leading-snug">{incident.title}</h2>
            </div>
            <div className="flex items-center gap-3">
              <DonutScore score={incident.cdcs_score} label="CDCS" />
              <button onClick={onClose} className="text-slate-400 hover:text-white text-xl leading-none">✕</button>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex gap-1 mt-4">
            {tabs.map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1.5 rounded-lg text-xs capitalize transition-colors ${
                  activeTab === tab ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/25' : 'text-slate-500 hover:text-white'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {activeTab === 'overview' && (
            <>
              {/* CDCS Breakdown */}
              <div className="mace-card p-4">
                <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">CDCS Domain Breakdown</div>
                <CDCSBreakdownChart scores={incident.sub_scores} />
                <div className="grid grid-cols-3 gap-2 mt-3">
                  {Object.entries(incident.sub_scores).map(([domain, score]) => (
                    <div key={domain} className="text-center">
                      <div className="text-xs text-slate-500">{domain}</div>
                      <div className="font-mono text-sm text-white">{(score * 10).toFixed(1)}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Kill chain */}
              {incident.kill_chain_stage && (
                <div className="mace-card p-4">
                  <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">Kill Chain Position</div>
                  <div className="flex items-center gap-1 flex-wrap">
                    {['recon','weaponize','delivery','exploit','install','c2','actions','exfiltration','impact'].map(stage => (
                      <div key={stage} className={`px-2 py-1 rounded text-xs font-mono border transition-all ${
                        incident.kill_chain_stage === stage
                          ? 'bg-red-500/20 border-red-500/40 text-red-400'
                          : 'bg-slate-800 border-slate-700 text-slate-500'
                      }`}>{stage}</div>
                    ))}
                  </div>
                </div>
              )}

              {/* Regulatory frameworks */}
              {incident.frameworks_triggered.length > 0 && (
                <div className="mace-card p-4">
                  <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">Regulatory Frameworks</div>
                  <div className="flex flex-wrap gap-2">
                    {incident.frameworks_triggered.map(f => (
                      <span key={f} className="text-xs bg-amber-500/10 text-amber-400 border border-amber-500/25 px-2 py-1 rounded font-mono">
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Status update */}
              <div className="mace-card p-4 space-y-3">
                <div className="text-xs text-slate-500 uppercase tracking-wider">Update Status</div>
                <select
                  value={newStatus}
                  onChange={e => setNewStatus(e.target.value as typeof incident.status)}
                  className="w-full bg-mace-bg border border-mace-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500/50"
                >
                  {['open','investigating','contained','eradicated','recovered','closed','false_positive'].map(s => (
                    <option key={s} value={s}>{s.replace('_', ' ')}</option>
                  ))}
                </select>
                <textarea
                  value={notes} onChange={e => setNotes(e.target.value)}
                  placeholder="Add response notes..."
                  className="w-full bg-mace-bg border border-mace-border rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 h-20 resize-none focus:outline-none focus:border-cyan-500/50"
                />
                <button
                  onClick={() => updateStatus.mutate()}
                  disabled={updateStatus.isPending}
                  className="bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/25 px-4 py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
                >
                  {updateStatus.isPending ? <Spinner size={14} /> : 'Update Status'}
                </button>
              </div>

              {/* Assign */}
              <div className="mace-card p-4 space-y-3">
                <div className="text-xs text-slate-500 uppercase tracking-wider">Assign Responder</div>
                <div className="flex gap-2">
                  <input
                    value={assignEmail} onChange={e => setAssignEmail(e.target.value)}
                    placeholder="analyst@company.com"
                    className="flex-1 bg-mace-bg border border-mace-border rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                  />
                  <button
                    onClick={() => assign.mutate()}
                    disabled={!assignEmail || assign.isPending}
                    className="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
                  >
                    Assign
                  </button>
                </div>
              </div>
            </>
          )}

          {activeTab === 'evidence' && (
            <>
              {!incident.has_evidence ? (
                <div className="text-slate-500 text-sm text-center py-8">No regulatory evidence generated for this incident</div>
              ) : evidenceLoading ? (
                <div className="text-center py-8"><Spinner /></div>
              ) : evidence ? (
                <>
                  <div className="mace-card p-4 space-y-3">
                    <div className="text-xs text-slate-500 uppercase tracking-wider">Chain of Custody</div>
                    <div className="font-mono text-xs text-green-400 break-all bg-mace-bg p-3 rounded-lg">
                      SHA-256: {evidence.chain_of_custody_hash}
                    </div>
                    {evidence.cert_in_reference && (
                      <div className="text-sm">
                        <span className="text-slate-500">CERT-In Ref: </span>
                        <span className="font-mono text-amber-400">{evidence.cert_in_reference}</span>
                      </div>
                    )}
                    {evidence.aecert_reference && (
                      <div className="text-sm">
                        <span className="text-slate-500">aeCERT Ref: </span>
                        <span className="font-mono text-blue-400">{evidence.aecert_reference}</span>
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-slate-500">SLA Status:</span>
                      {evidence.sla_breached
                        ? <span className="text-red-400 font-mono text-sm">⚠ BREACHED</span>
                        : <span className="text-green-400 font-mono text-sm">✓ On Time</span>
                      }
                    </div>
                  </div>

                  <div className="mace-card p-4 space-y-3">
                    <div className="text-xs text-slate-500 uppercase tracking-wider">Reporting Deadlines</div>
                    {Object.entries(evidence.reporting_deadlines).map(([fw, deadline]) => (
                      <div key={fw} className="flex items-center justify-between py-2 border-b border-mace-border last:border-0">
                        <span className="text-sm font-mono text-amber-400">{fw}</span>
                        <span className="text-xs text-slate-400">{fmtDate(deadline)}</span>
                      </div>
                    ))}
                  </div>

                  <div className="mace-card p-4 space-y-3">
                    <div className="text-xs text-slate-500 uppercase tracking-wider">Download Notification Drafts</div>
                    <div className="grid grid-cols-2 gap-2">
                      {Object.entries(evidence.drafts_available).map(([framework, available]) => (
                        available ? (
                          <button
                            key={framework}
                            onClick={() => downloadDraft(framework)}
                            disabled={downloadingDraft === framework}
                            className="flex items-center gap-2 px-3 py-2 bg-mace-bg hover:bg-slate-800 border border-mace-border rounded-lg text-xs text-slate-300 transition-colors disabled:opacity-50"
                          >
                            {downloadingDraft === framework ? <Spinner size={12} /> : '↓'}
                            <span className="font-mono uppercase">{framework.replace('_', '-')}</span>
                          </button>
                        ) : null
                      ))}
                    </div>
                  </div>
                </>
              ) : null}
            </>
          )}

          {activeTab === 'feedback' && (
            <div className="mace-card p-4 space-y-4">
              <div className="text-xs text-slate-500 uppercase tracking-wider">Adaptive Learning Feedback</div>
              <p className="text-sm text-slate-400">
                Provide feedback to improve MACE's adaptive weights. True positive confirmations
                reinforce the current scoring profile. False positives adjust weights to reduce noise.
              </p>
              {incident.confirmed_true_positive !== null ? (
                <div className="text-sm">
                  <span className="text-slate-500">Feedback recorded: </span>
                  <span className={incident.confirmed_true_positive ? 'text-green-400' : 'text-red-400'}>
                    {incident.confirmed_true_positive ? '✓ True Positive' : '✗ False Positive'}
                  </span>
                </div>
              ) : (
                <>
                  <textarea
                    value={notes} onChange={e => setNotes(e.target.value)}
                    placeholder="Optional notes for the learning system..."
                    className="w-full bg-mace-bg border border-mace-border rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 h-24 resize-none focus:outline-none focus:border-cyan-500/50"
                  />
                  <div className="flex gap-3">
                    <button
                      onClick={() => feedback.mutate(true)}
                      disabled={feedback.isPending}
                      className="flex-1 bg-green-500/10 hover:bg-green-500/20 text-green-400 border border-green-500/25 py-2 rounded-lg text-sm transition-colors"
                    >
                      ✓ True Positive
                    </button>
                    <button
                      onClick={() => feedback.mutate(false)}
                      disabled={feedback.isPending}
                      className="flex-1 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/25 py-2 rounded-lg text-sm transition-colors"
                    >
                      ✗ False Positive
                    </button>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
