// ── Auth ────────────────────────────────────────────────────────────
export interface AuthUser {
  user_id: string
  email: string
  full_name: string
  role: 'super_admin' | 'tenant_admin' | 'soc_analyst' | 'read_only' | 'api_user'
  tenant_id: string
  tenant_name: string
  tenant_slug: string
  jurisdiction: 'US' | 'IN' | 'EU' | 'CA' | 'AE'
  weight_profile: string
  plan: 'msme' | 'starter' | 'professional' | 'enterprise'
  mfa_enabled: boolean
}

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user_id: string
  tenant_id: string
  role: string
}

// ── Assets ──────────────────────────────────────────────────────────
export type AssetClass =
  | 'cloud_vm' | 'container' | 'kubernetes_node' | 'serverless'
  | 'endpoint' | 'server' | 'mobile' | 'network_device'
  | 'ot_ics' | 'iot_device' | 'database' | 'unknown'

export type AssetStatus = 'active' | 'stale' | 'shadow_it' | 'geo_anomaly' | 'decommissioned'

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export interface Asset {
  id: string
  canonical_id: string
  tenant_id: string
  hostname: string | null
  ip_address: string | null
  mac_address: string | null
  cloud_instance_id: string | null
  asset_class: AssetClass
  status: AssetStatus
  os: string | null
  owner: string | null
  sector: string | null
  jurisdiction: string
  data_classification: string
  is_internet_facing: boolean
  is_critical_infra: boolean
  acs_score: number
  entropy_score: number
  cdcs_score: number | null
  risk_level: RiskLevel | null
  source_set: string[]
  quorum_sources: number
  shadow_it_flag: boolean
  geo_velocity_flag: boolean
  max_geo_velocity_kmh: number
  critical_vuln_count: number
  high_vuln_count: number
  open_cves: string[]
  tags: Record<string, string>
  first_seen_at: string
  last_seen_at: string
  created_at: string
}

export interface AssetListResponse {
  items: Asset[]
  total: number
  page: number
  page_size: number
  has_next: boolean
}

// ── Incidents ───────────────────────────────────────────────────────
export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low'
export type IncidentStatus =
  | 'open' | 'investigating' | 'contained'
  | 'eradicated' | 'recovered' | 'closed' | 'false_positive'

export interface SubScores {
  V: number
  E: number
  I: number
  N: number
  C: number
  T: number
}

export interface Incident {
  id: string
  incident_ref: string
  title: string
  event_type: string
  cdcs_score: number
  severity: IncidentSeverity
  status: IncidentStatus
  kill_chain_stage: string | null
  dominant_domain: string | null
  sub_scores: SubScores
  frameworks_triggered: string[]
  jurisdictions: string[]
  assigned_to: string | null
  confirmed_true_positive: boolean | null
  detected_at: string
  resolved_at: string | null
  has_evidence: boolean
}

export interface IncidentListResponse {
  items: Incident[]
  total: number
  page: number
  page_size: number
  has_next: boolean
}

// ── Evidence ────────────────────────────────────────────────────────
export interface EvidenceRecord {
  incident_ref: string
  chain_of_custody_hash: string
  frameworks_triggered: string[]
  jurisdictions: string[]
  reporting_deadlines: Record<string, string>
  cert_in_reference: string | null
  aecert_reference: string | null
  status: string
  sla_breached: boolean
  evidenced_at: string
  drafts_available: Record<string, boolean>
}

// ── Regulatory Calendar ──────────────────────────────────────────────
export interface CalendarEntry {
  incident_id: string
  incident_ref: string
  framework: string
  deadline: string
  hours_remaining: number
  sla_breached: boolean
  jurisdiction: string
}

// ── Stats ───────────────────────────────────────────────────────────
export interface PlatformStats {
  assets: { total: number; limit: number }
  incidents: { open: number; critical: number }
  vulnerabilities: { open: number }
  engine: {
    total_assets: number
    total_incidents: number
    alert_rate: number
    true_positive_rate: number
    weight_profile: string
    current_weights: Record<string, number>
  }
  regulatory_calendar: CalendarEntry[]
}

// ── WebSocket ────────────────────────────────────────────────────────
export interface WSIncidentEvent {
  type: 'incident.new'
  incident_ref: string
  cdcs: number
  severity: string
  asset: string
  event_type: string
  cert_in_reference: string | null
  aecert_reference: string | null
  frameworks: string[]
  ts: string
}
