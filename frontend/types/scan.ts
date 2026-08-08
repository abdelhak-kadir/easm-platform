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
}

export interface ScanJob {
  id: number;
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
