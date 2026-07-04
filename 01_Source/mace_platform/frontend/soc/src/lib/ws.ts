import type { WSIncidentEvent } from '@/types'

type Handler = (event: WSIncidentEvent) => void

class MACEWebSocket {
  private ws: WebSocket | null = null
  private handlers: Handler[] = []
  private tenantId: string | null = null
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private reconnectDelay = 2000

  connect(tenantId: string) {
    this.tenantId = tenantId
    this._connect()
  }

  private _connect() {
    if (!this.tenantId) return
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${proto}://${location.host}/api/v1/correlate/ws/${this.tenantId}`

    this.ws = new WebSocket(url)

    this.ws.onopen = () => {
      console.log('[MACE WS] Connected')
      this.reconnectDelay = 2000
    }

    this.ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data) as WSIncidentEvent
        this.handlers.forEach(h => h(data))
      } catch {}
    }

    this.ws.onclose = () => {
      console.log('[MACE WS] Disconnected — reconnecting in', this.reconnectDelay, 'ms')
      this.reconnectTimer = setTimeout(() => {
        this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, 30000)
        this._connect()
      }, this.reconnectDelay)
    }

    // Heartbeat
    setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) this.ws.send('ping')
    }, 30000)
  }

  onIncident(handler: Handler) {
    this.handlers.push(handler)
    return () => { this.handlers = this.handlers.filter(h => h !== handler) }
  }

  disconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.ws?.close()
    this.ws = null
  }
}

export const maceWS = new MACEWebSocket()
