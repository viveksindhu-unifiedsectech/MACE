import axios from 'axios'
import type { TokenResponse, AuthUser, AssetListResponse, Asset, IncidentListResponse, Incident, EvidenceRecord, PlatformStats, CalendarEntry } from '@/types'

const BASE = import.meta.env.VITE_API_URL || '/api/v1'

export const api = axios.create({ baseURL: BASE })

// Auto-attach JWT from localStorage
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('mace_access_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

// Auto-refresh on 401
api.interceptors.response.use(
  r => r,
  async err => {
    if (err.response?.status === 401 && !err.config._retry) {
      err.config._retry = true
      try {
        const refresh = localStorage.getItem('mace_refresh_token')
        const { data } = await axios.post<TokenResponse>(`${BASE}/auth/refresh`, { refresh_token: refresh })
        localStorage.setItem('mace_access_token', data.access_token)
        localStorage.setItem('mace_refresh_token', data.refresh_token)
        err.config.headers.Authorization = `Bearer ${data.access_token}`
        return api(err.config)
      } catch {
        localStorage.clear()
        window.location.href = '/login'
      }
    }
    return Promise.reject(err)
  }
)

// ── Auth ──────────────────────────────────────────────────────────
export const authApi = {
  login: (email: string, password: string, tenantSlug: string) =>
    api.post<TokenResponse>('/auth/login', { email, password, tenant_slug: tenantSlug }),
  me: () => api.get<AuthUser>('/auth/me'),
  logout: () => api.post('/auth/logout'),
  register: (data: { email: string; password: string; full_name: string; tenant_name: string; tenant_slug: string; jurisdiction: string }) =>
    api.post<TokenResponse>('/auth/register', data),
}

// ── Assets ────────────────────────────────────────────────────────
export const assetsApi = {
  list: (params: Record<string, unknown>) => api.get<AssetListResponse>('/assets', { params }),
  get: (id: string) => api.get<Asset>(`/assets/${id}`),
  ingest: (data: Record<string, unknown>) => api.post('/assets/ingest', data),
  attachVuln: (assetId: string, vuln: Record<string, unknown>) =>
    api.post(`/assets/${assetId}/vulns`, vuln),
  shadowIt: () => api.get('/assets/shadow-it/list'),
  geoAnomalies: () => api.get('/assets/geo-anomalies/list'),
}

// ── Incidents ─────────────────────────────────────────────────────
export const incidentsApi = {
  list: (params?: Record<string, unknown>) =>
    api.get<IncidentListResponse>('/incidents', { params }),
  get: (id: string) => api.get<Incident>(`/incidents/${id}`),
  updateStatus: (id: string, status: string, notes?: string) =>
    api.patch(`/incidents/${id}/status`, null, { params: { new_status: status, notes } }),
  assign: (id: string, email: string) =>
    api.post(`/incidents/${id}/assign`, null, { params: { assignee_email: email } }),
  getEvidence: (id: string) => api.get<EvidenceRecord>(`/incidents/${id}/evidence`),
  downloadDraft: (id: string, framework: string) =>
    api.get<string>(`/incidents/${id}/evidence/${framework}/draft`, { responseType: 'text' }),
  regulatoryCalendar: () => api.get<{ items: CalendarEntry[] }>('/incidents/regulatory-calendar'),
  submitFeedback: (incidentId: string, confirmed: boolean, notes?: string) =>
    api.post('/correlate/feedback', { incident_id: incidentId, confirmed_true_positive: confirmed, notes }),
}

// ── Admin / Stats ─────────────────────────────────────────────────
export const adminApi = {
  stats: () => api.get<PlatformStats>('/admin/stats'),
  tenant: () => api.get('/admin/tenant'),
  users: () => api.get('/admin/users'),
  auditLog: (params?: Record<string, unknown>) => api.get('/admin/audit-log', { params }),
  connectors: () => api.get('/admin/connectors'),
}
