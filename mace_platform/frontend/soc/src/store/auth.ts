import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { AuthUser } from '@/types'

interface AuthState {
  user: AuthUser | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  setTokens: (access: string, refresh: string) => void
  setUser: (user: AuthUser) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      setTokens: (access, refresh) => {
        localStorage.setItem('mace_access_token', access)
        localStorage.setItem('mace_refresh_token', refresh)
        set({ accessToken: access, refreshToken: refresh, isAuthenticated: true })
      },
      setUser: (user) => set({ user }),
      logout: () => {
        localStorage.removeItem('mace_access_token')
        localStorage.removeItem('mace_refresh_token')
        set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false })
      },
    }),
    { name: 'mace-auth', partialize: (s) => ({ accessToken: s.accessToken, refreshToken: s.refreshToken }) }
  )
)
