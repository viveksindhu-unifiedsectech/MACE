import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import { Spinner } from '@/components/ui'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [slug, setSlug] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const { setToken, setUser } = useAuthStore()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email || !password || !slug) { setError('All fields required'); return }
    setLoading(true); setError('')
    try {
      const { data: tokens } = await authApi.login(email, password, slug)
      setToken(tokens.access_token)
      const { data: user } = await authApi.me()
      if (!['tenant_admin','super_admin'].includes(user.role)) { setError('Admin access required'); setLoading(false); return }
      setUser(user)
      navigate('/')
    } catch (err: unknown) {
      const msg = (err as {response?:{data?:{detail?:string}}})?.response?.data?.detail
      setError(typeof msg === 'string' ? msg : 'Login failed')
    } finally { setLoading(false) }
  }

  return (
    <div className="min-h-screen adm-bg flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 mb-4">
            <span className="text-white font-bold text-2xl">A</span>
          </div>
          <h1 className="text-2xl font-bold text-white">MACE Admin</h1>
          <p className="text-adm-muted text-sm mt-1">Platform Administration Console</p>
        </div>
        <div className="adm-card p-8 space-y-4">
          <form onSubmit={handleSubmit} className="space-y-4">
            {[
              { label:'Workspace Slug', value:slug, set:setSlug, placeholder:'your-org-slug', mono:true },
              { label:'Admin Email', value:email, set:setEmail, placeholder:'admin@yourorg.com', type:'email' },
              { label:'Password', value:password, set:setPassword, placeholder:'••••••••', type:'password' },
            ].map(({ label, value, set, placeholder, type='text', mono }) => (
              <div key={label}>
                <label className="adm-label">{label}</label>
                <input type={type} value={value} onChange={e => set(e.target.value)}
                  placeholder={placeholder}
                  className={`adm-input ${mono ? 'font-mono' : ''}`} />
              </div>
            ))}
            {error && <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">{error}</div>}
            <button type="submit" disabled={loading}
              className="adm-btn-primary w-full flex items-center justify-center gap-2">
              {loading ? <><Spinner size={16}/> Authenticating...</> : 'Sign In to Admin'}
            </button>
          </form>
          <div className="text-center text-xs text-adm-muted">Requires tenant_admin or super_admin role</div>
        </div>
      </div>
    </div>
  )
}
