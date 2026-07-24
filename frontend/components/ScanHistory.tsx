import { useState, useEffect, useCallback } from "react";
import { Asset, ScanJob } from "../types/scan";
import { timeAgo } from "../lib/time";

const STATUS_COLOR: Record<string, string> = {
  completed: "var(--signal)",
  failed: "#E0525C",
  running: "#D9BB4C",
  pending: "var(--muted)",
};

export default function ScanHistory({
  apiBase,
  asset,
  onSelectJob,
  refreshKey,
  activeJobId,
  onJobsLoaded,
  onJumpToAsset,
}: {
  apiBase: string;
  asset: Asset | null;
  onSelectJob: (job: ScanJob) => void;
  refreshKey: number;
  activeJobId?: number | null;
  onJobsLoaded?: (jobs: ScanJob[]) => void;
  onJumpToAsset?: (assetId: number) => void;
}) {
  const [jobs, setJobs] = useState<ScanJob[]>([]);

  const loadJobs = useCallback(() => {
    if (!asset) return;
    fetch(`${apiBase}/scans/asset/${asset.id}`)
      .then((r) => r.json())
      .then((data: ScanJob[]) => {
        setJobs(data);
        onJobsLoaded?.(data);
      })
      .catch(() => {
        setJobs([]);
        onJobsLoaded?.([]);
      });
  }, [apiBase, asset, onJobsLoaded]);

  useEffect(() => {
    loadJobs();
  }, [loadJobs, refreshKey]);

  if (!asset) return null;

  if (jobs.length === 0) {
    return (
      <p className="mono text-xs px-3 py-3 mb-6" style={{ color: "var(--muted)", border: "1px dashed var(--hairline)" }}>
        // no previous scans for this target — run one above
      </p>
    );
  }

  return (
    <div className="mb-6">
      <div className="eyebrow mb-1.5">SCAN HISTORY</div>
      <div className="panel divide-y" style={{ borderColor: "var(--hairline)" }}>
        {jobs.map((j) => (
          <div key={j.id}>
            <button
              onClick={() => onSelectJob(j)}
              className="mono w-full text-left text-sm px-3 py-2 flex justify-between items-center transition-colors"
              style={{
                background: activeJobId === j.id ? "var(--panel-alt)" : "transparent",
              }}
            >
              <span className="flex items-center gap-2">
                <span>{j.tool}</span>
                <span style={{ color: "var(--muted)" }}>#{j.id}</span>
                {j.completed_at && <span className="text-xs" style={{ color: "var(--muted)" }}>{timeAgo(j.completed_at)}</span>}
              </span>
              <span className="text-xs tracking-wider" style={{ color: STATUS_COLOR[j.status] || "var(--muted)" }}>
                {j.status.toUpperCase()}
              </span>
            </button>

            {j.spawned_asset_value && (
              <div
                className="mono text-xs px-3 pb-2 flex items-center gap-2 flex-wrap"
                style={{ color: "var(--muted)" }}
              >
                <span>
                  → resolved IP {j.spawned_asset_value} · {j.spawned_job_tool}{" "}
                  <span style={{ color: STATUS_COLOR[j.spawned_job_status || ""] || "var(--muted)" }}>
                    {(j.spawned_job_status || "").toUpperCase()}
                  </span>
                </span>
                {j.spawned_asset_id != null && (
                  <button
                    onClick={() => onJumpToAsset?.(j.spawned_asset_id!)}
                    className="underline"
                    style={{ color: "var(--signal)" }}
                  >
                    view
                  </button>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
