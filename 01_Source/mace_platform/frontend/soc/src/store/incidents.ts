import { create } from 'zustand'
import type { WSIncidentEvent } from '@/types'

interface IncidentsState {
  liveEvents: WSIncidentEvent[]
  unreadCount: number
  addLiveEvent: (event: WSIncidentEvent) => void
  markRead: () => void
  wsConnected: boolean
  setWsConnected: (v: boolean) => void
}

export const useIncidentsStore = create<IncidentsState>((set) => ({
  liveEvents: [],
  unreadCount: 0,
  wsConnected: false,
  addLiveEvent: (event) => set(s => ({
    liveEvents: [event, ...s.liveEvents].slice(0, 100),
    unreadCount: s.unreadCount + 1,
  })),
  markRead: () => set({ unreadCount: 0 }),
  setWsConnected: (v) => set({ wsConnected: v }),
}))
