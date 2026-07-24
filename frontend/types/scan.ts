export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Asset {
  id: number;
  value: string;
  asset_type: string;
}

export interface ScanJob {
  id: number;
  tool: string;
  status: string;
  created_at?: string;
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
