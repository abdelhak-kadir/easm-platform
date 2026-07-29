import { useState, useEffect, useCallback } from "react";
import { Asset, ScanJob } from "../types/scan";
import { timeAgo } from "../lib/time";
import { toolLabel } from "../lib/labels";

const STATUS_STYLE: Record<string, { color: string; bg: string; label: string }> = {
  completed: { color: "var(--success)", bg: "var(--success-dim)", label: "TERMINÉE" },
  failed: { color: "var(--danger)", bg: "var(--danger-dim)", label: "ÉCHOUÉE" },
  running: { color: "var(--warning)", bg: "var(--warning-dim)", label: "EN COURS" },
  pending: { color: "var(--muted)", bg: "var(--panel-alt)", label: "EN ATTENTE" },
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
        Aucune analyse précédente pour cette cible — lancez-en une ci-dessus pour commencer.
      </p>
    );
  }

  return (
    <div className="mb-6">
      <p className="eyebrow mb-2">Historique des analyses</p>
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
                <span className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium">{toolLabel(j.tool)}</span>
                  <span className="mono text-xs" style={{ color: "var(--faint)" }}>
                    {j.tool} · #{j.id}
                  </span>
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
                  {style.label}
                </span>
              </button>

              {j.spawned_asset_value && (
                <div className="text-xs px-4 pb-2.5 flex items-center gap-2 flex-wrap" style={{ color: "var(--muted)" }}>
                  <span>
                    → IP résolue <span className="mono">{j.spawned_asset_value}</span> · {toolLabel(j.spawned_job_tool || "")}{" "}
                    <span
                      className="font-semibold"
                      style={{ color: (STATUS_STYLE[j.spawned_job_status || ""] || STATUS_STYLE.pending).color }}
                    >
                      {(STATUS_STYLE[j.spawned_job_status || ""] || STATUS_STYLE.pending).label}
                    </span>
                  </span>
                  {j.spawned_asset_id != null && (
                    <button
                      onClick={() => onJumpToAsset?.(j.spawned_asset_id!)}
                      className="font-medium underline"
                      style={{ color: "var(--signal)" }}
                    >
                      voir
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
