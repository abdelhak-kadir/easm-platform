export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type AssetStatus = "pending" | "running" | "done";

export type AssetType =
  | "domain"
  | "subdomain"
  | "ip"
  | "email"
  | "service"
  | "technology";

export interface Asset {
  id: number;
  value: string;
  asset_type: string;
  status: AssetStatus;
  discovery_run_id: number | null;
  root_asset_id?: number | null;
}

export interface ScanJob {
  id: number;
  asset_id: number;
  tool: string;
  status: string;
  error_message?: string | null;
  created_at?: string;
  started_at?: string;
  completed_at?: string;
  spawned_asset_id?: number | null;
  spawned_asset_value?: string | null;
  spawned_job_id?: number | null;
  spawned_job_tool?: string | null;
  spawned_job_status?: string | null;
}

export interface Finding {
  id: number;
  finding_type: string;
  title: string;
  severity: Severity;
  data: Record<string, any>;
}

export interface ScanResults {
  job_id: number;
  status: string;
  version: number | null;
  findings: Finding[];
}

// GET /scans/{job_id}/suggest-assets
export interface SuggestedAsset {
  ip: string;
  org: string | null;
  hostnames: string[];
  ports: number[];
  products: string[];
  already_tracked: boolean;
  is_source: boolean;
}

export interface SuggestAssetsResponse {
  job_id: number;
  by: string;
  query_value: string;
  is_shared_hosting_warning: boolean;
  candidates: SuggestedAsset[];
}

// POST /scans/suggest-assets/accept
export interface AcceptSuggestedResult {
  asset_id: number;
  value: string;
  created: boolean;
  queued: { task_id: string; job_id: number; tool: string }[];
}

export interface AcceptSuggestedResponse {
  created: AcceptSuggestedResult[];
}

// GET /scans/{job_id}/suggest-discovered
export interface DiscoveredCandidate {
  value: string;
  already_tracked: boolean;
}

export interface SuggestDiscoveredResponse {
  job_id: number;
  category: string;
  candidates: DiscoveredCandidate[];
}

// POST /scans/suggest-discovered/accept
export interface AcceptDiscoveredResult {
  asset_id: number;
  value: string;
  created: boolean;
  queued: { task_id: string; job_id: number; tool: string }[];
}

export interface AcceptDiscoveredResponse {
  created: AcceptDiscoveredResult[];
}

// GET /scans/discovery/{run_id}
export interface DiscoveryRunStatus {
  id: number;
  root_asset: { id: number | null; value: string | null };
  round_number: number;
  max_rounds: number;
  status: string; // "running" | "completed" | "max_rounds_reached" | "cancelled"
  assets: { total: number; pending: number; running: number; done: number };
  active_jobs: number;
  created_at: string | null;
  completed_at: string | null;
}

// GET /assets/{asset_id}/risk
export interface AssetRisk {
  asset_id: number;
  score: number;
  max_score: number;
  breakdown: Record<string, number>;
  finding_count: number;
  cve_count: number;
  exposed_ports: number;
  last_scan: string | null;
}

// GET /scans/asset/{asset_id}/diff
export interface DiffChangedKey {
  key: string;
  old?: any;
  new?: any;
  added_items?: string[];
  removed_items?: string[];
}

export interface DiffEntry {
  tool: string;
  latest_version: number;
  previous_version: number;
  added_keys: string[];
  removed_keys: string[];
  changed_keys: DiffChangedKey[];
}

export interface AssetDiffResponse {
  asset_id: number;
  diffs: DiffEntry[];
}

// GET /assets/{asset_id}/dashboard
export interface DashboardToolSummary {
  tool: string;
  category: string;
  applicable: boolean;
  latest_job: ScanJob | null;
  latest_status: string | null;
  job_count: number;
  finding_count: number;
  severities: Record<Severity, number>;
  last_completed_at: string | null;
}

export interface RelatedAssetGroup {
  asset: Asset;
  relation: "child" | "parent" | "both";
  links: ScanJob[];
  scans: ScanJob[];
  summary: {
    latest_status: string | null;
    finding_count: number;
    severities: Record<Severity, number>;
  };
}

export interface AssetDashboardResponse {
  asset: Asset;
  scans: ScanJob[];
  related_assets: RelatedAssetGroup[];
  tool_summary: DashboardToolSummary[];
  risk: AssetRisk | null;
  generated_at: string;
}

// GET /assets/{asset_id}/reputation
export interface ReputationZone {
  zone: string;
  code?: string;
  query?: string;
  reason?: string;
}

export interface ReputationIpEntry {
  ip: string;
  asset_id: number;
  listed_count: number;
  tor_exit: boolean;
  abuseipdb_score?: number | null;
  zones_checked?: number | null;
  zones_with_errors?: number | null;
  last_checked: string | null;
  zones: ReputationZone[];
  abuseipdb?: {
    score: number;
    total_reports?: number | null;
    distinct_users?: number | null;
    is_whitelisted?: boolean | null;
    usage_type?: string | null;
  };
}

export interface ReputationZoneGroup {
  zone: string;
  count: number;
  listed_ips: string[];
}

export interface AssetReputationResponse {
  root_asset: { id: number; value: string | null; asset_type: string | null };
  total_ips: number;
  listed_ips: number;
  total_zone_listings: number;
  ips: ReputationIpEntry[];
  by_zone: ReputationZoneGroup[];
  unchecked_ips: string[];
  generated_at: string;
}
