import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import { Spinner } from '@/components/ui/Spinner'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [tenantSlug, setTenantSlug] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const { setTokens, setUser } = useAuthStore()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email || !password || !tenantSlug) { setError('All fields required'); return }
    setLoading(true); setError('')
    try {
      const { data: tokens } = await authApi.login(email, password, tenantSlug)
      setTokens(tokens.access_token, tokens.refresh_token)
      const { data: user } = await authApi.me()
      setUser(user)
      navigate('/')
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(typeof msg === 'string' ? msg : 'Login failed. Check your credentials.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-mace-bg flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 mb-4">
            <span className="text-white font-bold text-2xl">M</span>
          </div>
          <h1 className="text-2xl font-bold text-white">MACE SOC</h1>
          <p className="text-slate-500 text-sm mt-1">UnifiedSec MACE v2 Security Operations</p>
        </div>

        {/* Form */}
        <div className="mace-card p-8 space-y-5">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs text-slate-500 uppercase tracking-wider block mb-1.5">Workspace</label>
              <input
                value={tenantSlug} onChange={e => setTenantSlug(e.target.value)}
                placeholder="your-org-slug"
                className="w-full bg-mace-bg border border-mace-border rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 font-mono"
              />
            </div>
            <div>
              <label className="text-xs text-slate-500 uppercase tracking-wider block mb-1.5">Email</label>
              <input
                type="email" value={email} onChange={e => setEmail(e.target.value)}
                placeholder="analyst@yourorg.com"
                className="w-full bg-mace-bg border border-mace-border rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/50"
              />
            </div>
            <div>
              <label className="text-xs text-slate-500 uppercase tracking-wider block mb-1.5">Password</label>
              <input
                type="password" value={password} onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-mace-bg border border-mace-border rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/50"
              />
            </div>

            {error && (
              <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                {error}
              </div>
            )}

            <button
              type="submit" disabled={loading}
              className="w-full bg-cyan-500 hover:bg-cyan-400 text-mace-bg font-semibold py-2.5 rounded-lg text-sm transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {loading ? <><Spinner size={16} /> Authenticating...</> : 'Sign In to SOC'}
            </button>
          </form>

          <div className="text-center text-xs text-slate-600">
            Patent IN/2026/UNISEC/MACE-001 · UnifiedSec Technologies
          </div>
        </div>

        {/* Multi-jurisdiction note */}
        <div className="mt-4 flex justify-center gap-3 text-xs text-slate-600">
          <span>🇺🇸 US</span><span>🇦🇪 UAE</span><span>🇪🇺 EU</span><span>🇮🇳 India</span><span>🇨🇦 Canada</span>
        </div>
      </div>
    </div>
  )
}
