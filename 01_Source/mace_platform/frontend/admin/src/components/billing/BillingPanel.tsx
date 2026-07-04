import { useQuery, useMutation } from '@tanstack/react-query'
import { billingApi, adminApi } from '@/lib/api'
import { StatCard, Spinner } from '@/components/ui'
import { fmtDate, planLabel, jurisdictionLabel } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'
import type { Subscription } from '@/types'

const PLANS = [
  { id:'starter', name:'Starter', price:'$12/asset/yr', limit:'500 assets', color:'#6366f1', features:['MACE correlation engine','5 data connectors','Regulatory calendar','Email support'] },
  { id:'professional', name:'Professional', price:'$9/asset/yr', limit:'5,000 assets', color:'#8b5cf6', featured:true, features:['Everything in Starter','10 data connectors','Priority support','Advanced analytics','SOC 2 report'] },
  { id:'enterprise', name:'Enterprise', price:'Custom', limit:'Unlimited', color:'#06b6d4', features:['Everything in Professional','FedRAMP / GovCloud','HIPAA BAA','Custom SLA','Dedicated CSM','API rate limit increase'] },
]

export function BillingPanel() {
  const { user } = useAuthStore()

  const { data: sub, isLoading } = useQuery<Subscription>({
    queryKey: ['subscription'],
    queryFn: () => billingApi.subscription().then(r => r.data)
  })

  const checkout = useMutation({
    mutationFn: ({ plan, jurisdiction }: { plan:string; jurisdiction:string }) =>
      billingApi.createCheckout(plan, jurisdiction).then(r => { window.location.href = r.data.checkout_url }),
  })

  if (isLoading) return <div className="flex justify-center py-12"><Spinner /></div>

  const usagePct = sub?.asset_limit ? Math.round(((sub.assets_used||0) / sub.asset_limit) * 100) : 0

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Current subscription */}
      {sub?.status && sub.status !== 'no_subscription' ? (
        <div className="adm-card p-6">
          <div className="flex items-start justify-between mb-4">
            <div>
              <div className="text-sm text-adm-muted mb-1">Current Plan</div>
              <div className="text-2xl font-bold text-white">{planLabel(sub.plan_name)}</div>
            </div>
            <span className={`text-sm px-3 py-1 rounded-full border font-medium ${
              sub.status === 'active' ? 'text-green-400 bg-green-500/10 border-green-500/25' :
              sub.status === 'trialing' ? 'text-amber-400 bg-amber-500/10 border-amber-500/25' :
              'text-red-400 bg-red-500/10 border-red-500/25'
            }`}>{sub.status}</span>
          </div>

          <div className="grid grid-cols-3 gap-4 mb-4">
            <StatCard label="Assets Used" value={`${sub.assets_used||0}`} sub={`of ${sub.asset_limit} limit`} color="#6366f1" />
            <StatCard label="Usage" value={`${usagePct}%`} color={usagePct > 80 ? '#ef4444' : '#52c41a'} />
            <StatCard label="Price" value={sub.price_per_asset_usd ? `$${sub.price_per_asset_usd}/asset` : 'Custom'} color="#e2e8f0" />
          </div>

          {/* Usage bar */}
          <div className="mb-4">
            <div className="flex justify-between text-xs text-adm-muted mb-1">
              <span>Asset usage</span>
              <span>{sub.assets_used||0} / {sub.asset_limit}</span>
            </div>
            <div className="h-2 bg-adm-bg rounded-full overflow-hidden border border-adm-border">
              <div className="h-full rounded-full transition-all duration-500" style={{
                width: `${Math.min(usagePct, 100)}%`,
                backgroundColor: usagePct > 80 ? '#ef4444' : '#6366f1'
              }} />
            </div>
          </div>

          {sub.current_period_end && (
            <div className="text-xs text-adm-muted">
              Billing period ends: <span className="text-adm-text">{fmtDate(sub.current_period_end)}</span>
            </div>
          )}
          {sub.trial_end && (
            <div className="text-xs text-amber-400 mt-1">
              Trial ends: {fmtDate(sub.trial_end)}
            </div>
          )}
        </div>
      ) : (
        <div className="adm-card p-6 border-amber-500/30 bg-amber-500/5">
          <div className="text-amber-400 font-semibold mb-1">No Active Subscription</div>
          <div className="text-sm text-adm-muted">Choose a plan to activate your MACE platform.</div>
        </div>
      )}

      {/* Upgrade plans */}
      <div>
        <h3 className="font-semibold text-white mb-4">Plans</h3>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {PLANS.map(plan => (
            <div key={plan.id} className={`adm-card p-5 flex flex-col relative ${plan.featured ? 'border-indigo-500/50' : ''}`}>
              {plan.featured && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-indigo-500 text-white text-xs px-3 py-0.5 rounded-full">Most Popular</div>
              )}
              <div className="mb-4">
                <div className="text-lg font-bold text-white">{plan.name}</div>
                <div className="text-2xl font-mono mt-1" style={{color: plan.color}}>{plan.price}</div>
                <div className="text-xs text-adm-muted mt-1">{plan.limit}</div>
              </div>
              <ul className="flex-1 space-y-2 mb-5">
                {plan.features.map(f => (
                  <li key={f} className="flex items-start gap-2 text-xs text-adm-muted">
                    <span className="text-green-400 mt-0.5 flex-shrink-0">✓</span>{f}
                  </li>
                ))}
              </ul>
              <button
                className="w-full py-2 rounded-lg text-sm font-medium transition-colors"
                style={{ backgroundColor: `${plan.color}20`, color: plan.color, border: `1px solid ${plan.color}40` }}
                onClick={() => plan.id !== 'enterprise' && checkout.mutate({ plan: plan.id, jurisdiction: user?.jurisdiction || 'US' })}
                disabled={checkout.isPending || plan.id === 'enterprise'}
              >
                {plan.id === 'enterprise' ? 'Contact Sales' : (checkout.isPending ? 'Redirecting...' : `Upgrade to ${plan.name}`)}
              </button>
            </div>
          ))}
        </div>
        <p className="text-xs text-adm-muted mt-4 text-center">
          India pricing: ₹500/asset/yr · UAE/EU pricing available · All plans include 14-day trial
        </p>
      </div>
    </div>
  )
}
