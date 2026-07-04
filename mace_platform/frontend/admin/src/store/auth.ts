import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { AdminUser } from '@/types'
interface S { user: AdminUser|null; token: string|null; isAuth: boolean; setToken:(t:string)=>void; setUser:(u:AdminUser)=>void; logout:()=>void }
export const useAuthStore = create<S>()(persist(
  (set) => ({
    user: null, token: null, isAuth: false,
    setToken: (t) => { localStorage.setItem('mace_admin_token', t); set({ token: t, isAuth: true }) },
    setUser: (u) => set({ user: u }),
    logout: () => { localStorage.clear(); set({ user: null, token: null, isAuth: false }) },
  }),
  { name: 'mace-admin-auth', partialize: s => ({ token: s.token }) }
))
