import axios from 'axios'
const BASE = import.meta.env.VITE_API_URL || '/api/v1'
export const api = axios.create({ baseURL: BASE })
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('mace_admin_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})
api.interceptors.response.use(r => r, async err => {
  if (err.response?.status === 401) { localStorage.clear(); window.location.href = '/login' }
  return Promise.reject(err)
})
export const authApi = {
  login: (email: string, password: string, slug: string) => api.post('/auth/login', { email, password, tenant_slug: slug }),
  me: () => api.get('/auth/me'),
  logout: () => api.post('/auth/logout'),
}
export const adminApi = {
  stats: () => api.get('/admin/stats'),
  tenant: () => api.get('/admin/tenant'),
  updateConfig: (params: Record<string,unknown>) => api.patch('/admin/tenant/config', null, { params }),
  users: () => api.get('/admin/users'),
  createUser: (params: Record<string,unknown>) => api.post('/admin/users', null, { params }),
  updateUser: (id: string, params: Record<string,unknown>) => api.patch(`/admin/users/${id}`, null, { params }),
  apiKeys: () => api.get('/admin/api-keys'),
  createApiKey: (name: string, scopes: string[]) => api.post('/admin/api-keys', null, { params: { name, scopes } }),
  revokeApiKey: (id: string) => api.delete(`/admin/api-keys/${id}`),
  connectors: () => api.get('/admin/connectors'),
  createConnector: (params: Record<string,unknown>) => api.post('/admin/connectors', null, { params }),
  deleteConnector: (id: string) => api.delete(`/admin/connectors/${id}`),
  auditLog: (params?: Record<string,unknown>) => api.get('/admin/audit-log', { params }),
}
export const billingApi = {
  subscription: () => api.get('/billing/subscription'),
  createCheckout: (plan: string, jurisdiction: string) => api.post('/billing/create-checkout-session', null, { params: { plan, jurisdiction } }),
}
