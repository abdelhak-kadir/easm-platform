import { useState, useEffect, useCallback } from "react";
import { Asset, ScanJob } from "../types/scan";
import { timeAgo } from "../lib/time";

const STATUS_STYLE: Record<string, { color: string; bg: string }> = {
  completed: { color: "var(--success)", bg: "var(--success-dim)" },
  failed: { color: "var(--danger)", bg: "var(--danger-dim)" },
  running: { color: "var(--warning)", bg: "var(--warning-dim)" },
  pending: { color: "var(--muted)", bg: "var(--panel-alt)" },
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
      <p
        className="text-xs px-4 py-4 mb-6 rounded-lg text-center"
        style={{ color: "var(--muted)", border: "1px dashed var(--hairline)" }}
      >
        No previous scans for this target — run one above to get started.
      </p>
    );
  }

  return (
    <div className="mb-6">
      <p className="eyebrow mb-2">Scan history</p>
      <div className="panel divide-y" style={{ borderColor: "var(--hairline)" }}>
        {jobs.map((j) => {
          const style = STATUS_STYLE[j.status] || STATUS_STYLE.pending;
          return (
            <div key={j.id}>
              <button
                onClick={() => onSelectJob(j)}
                className="w-full text-left text-sm px-4 py-2.5 flex justify-between items-center transition-colors"
                style={{
                  background: activeJobId === j.id ? "var(--panel-alt)" : "transparent",
                }}
              >
                <span className="flex items-center gap-2">
                  <span className="font-medium">{j.tool}</span>
                  <span style={{ color: "var(--faint)" }}>#{j.id}</span>
                  {j.completed_at && (
                    <span className="text-xs" style={{ color: "var(--muted)" }}>
                      {timeAgo(j.completed_at)}
                    </span>
                  )}
                </span>
                <span
                  className="text-[11px] font-semibold px-2 py-1 rounded-full"
                  style={{ color: style.color, background: style.bg }}
                >
                  {j.status.toUpperCase()}
                </span>
              </button>

              {j.spawned_asset_value && (
                <div className="text-xs px-4 pb-2.5 flex items-center gap-2 flex-wrap" style={{ color: "var(--muted)" }}>
                  <span>
                    → resolved IP <span className="mono">{j.spawned_asset_value}</span> · {j.spawned_job_tool}{" "}
                    <span
                      className="font-semibold"
                      style={{ color: (STATUS_STYLE[j.spawned_job_status || ""] || STATUS_STYLE.pending).color }}
                    >
                      {(j.spawned_job_status || "").toUpperCase()}
                    </span>
                  </span>
                  {j.spawned_asset_id != null && (
                    <button
                      onClick={() => onJumpToAsset?.(j.spawned_asset_id!)}
                      className="font-medium underline"
                      style={{ color: "var(--signal)" }}
                    >
                      view
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
