import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/store/auth'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'
import TenantPage from '@/pages/TenantPage'
import UsersPage from '@/pages/UsersPage'
import APIKeysPage from '@/pages/APIKeysPage'
import ConnectorsPage from '@/pages/ConnectorsPage'
import BillingPage from '@/pages/BillingPage'
import AuditPage from '@/pages/AuditPage'

function Guard({ children }: { children: React.ReactNode }) {
  return useAuthStore(s => s.isAuth) ? <>{children}</> : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Guard><Dashboard /></Guard>} />
      <Route path="/tenant" element={<Guard><TenantPage /></Guard>} />
      <Route path="/users" element={<Guard><UsersPage /></Guard>} />
      <Route path="/api-keys" element={<Guard><APIKeysPage /></Guard>} />
      <Route path="/connectors" element={<Guard><ConnectorsPage /></Guard>} />
      <Route path="/billing" element={<Guard><BillingPage /></Guard>} />
      <Route path="/audit" element={<Guard><AuditPage /></Guard>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
