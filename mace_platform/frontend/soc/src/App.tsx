import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/store/auth'
import Login from '@/pages/Login'
import Overview from '@/pages/Overview'
import Assets from '@/pages/Assets'
import Incidents from '@/pages/Incidents'
import Compliance from '@/pages/Compliance'
import ShadowIT from '@/pages/ShadowIT'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore()
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<RequireAuth><Overview /></RequireAuth>} />
      <Route path="/assets" element={<RequireAuth><Assets /></RequireAuth>} />
      <Route path="/incidents" element={<RequireAuth><Incidents /></RequireAuth>} />
      <Route path="/compliance" element={<RequireAuth><Compliance /></RequireAuth>} />
      <Route path="/shadow-it" element={<RequireAuth><ShadowIT /></RequireAuth>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
