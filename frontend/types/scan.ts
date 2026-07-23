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
