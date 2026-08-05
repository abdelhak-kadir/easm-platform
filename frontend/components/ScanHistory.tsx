import { useState, useEffect, useCallback } from "react";
import { Asset, ScanJob } from "../types/scan";
import { timeAgo } from "../lib/time";
import { toolLabel } from "../lib/labels";

const STATUS_STYLE: Record<string, { color: string; bg: string; label: string }> = {
  completed: { color: "var(--success)", bg: "var(--success-dim)", label: "Terminée" },
  failed: { color: "var(--critical)", bg: "var(--critical-dim)", label: "Échouée" },
  running: { color: "var(--high)", bg: "var(--high-dim)", label: "En cours" },
  pending: { color: "var(--text-secondary)", bg: "var(--panel-dim)", label: "En attente" },
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
        className="text-xs px-4 py-6 mb-6 rounded-lg text-center"
        style={{ color: "var(--text-secondary)", border: "1px dashed var(--border)" }}
      >
        Aucune analyse précédente lancez-en une ci-dessus.
      </p>
    );
  }

  return (
    <div className="mb-6">
      <p className="eyebrow mb-3">Historique des analyses</p>
      <div className="panel divide-y" style={{ borderColor: "var(--border)" }}>
        {jobs.map((j) => {
          const style = STATUS_STYLE[j.status] || STATUS_STYLE.pending;
          const isActive = activeJobId === j.id;
          const isRunning = j.status === "running" || j.status === "pending";

          return (
            <div key={j.id}>
              <button
                onClick={() => onSelectJob(j)}
                className="w-full text-left text-sm px-4 py-3 flex items-center gap-3 transition-colors"
                style={{
                  background: isActive ? "var(--brand-dim)" : "transparent",
                  borderLeft: `3px solid ${isActive ? "var(--brand-accent)" : "transparent"}`,
                }}
              >
                {/* Status dot */}
                <span
                  className={`shrink-0 ${isRunning ? "status-dot status-dot--live" : ""}`}
                  style={isRunning ? undefined : {
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: style.color,
                    display: "inline-block",
                  }}
                />

                {/* Tool info */}
                <span className="flex-1 flex items-center gap-2 min-w-0">
                  <span className="font-semibold truncate" style={{ color: "var(--text-primary)" }}>
                    {toolLabel(j.tool)}
                  </span>
                  <span
                    className="text-xs shrink-0"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    {j.completed_at ? timeAgo(j.completed_at) : "—"}
                  </span>
                </span>

                {/* Status pill */}
                <span
                  className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full shrink-0"
                  style={{ color: style.color, background: style.bg }}
                >
                  {style.label}
                </span>

                {/* Cancel button — span to avoid nested <button> */}
                {isRunning && (
                  <span
                    role="button"
                    tabIndex={0}
                    onClick={(e) => {
                      e.stopPropagation();
                      fetch(`${apiBase}/scans/${j.id}/cancel`, { method: "POST" })
                        .then(() => loadJobs());
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.stopPropagation();
                        fetch(`${apiBase}/scans/${j.id}/cancel`, { method: "POST" })
                          .then(() => loadJobs());
                      }
                    }}
                    className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full shrink-0 transition-colors cursor-pointer"
                    style={{
                      color: "var(--critical)",
                      background: "var(--critical-dim)",
                      border: "1px solid var(--critical)",
                    }}
                    title="Annuler cette analyse"
                  >
                    ✕
                  </span>
                )}
              </button>

              {/* Spawned asset chain */}
              {j.spawned_asset_value && (
                <div
                  className="text-[11px] px-4 pb-2.5 ml-9 flex items-center gap-2 flex-wrap"
                  style={{ color: "var(--text-secondary)" }}
                >
                  <span>
                    → IP résolue{" "}
                    <span className="mono font-medium" style={{ color: "var(--text-primary)" }}>
                      {j.spawned_asset_value}
                    </span>{" "}
                    · {toolLabel(j.spawned_job_tool || "")}{" "}
                    <span
                      className="font-semibold"
                      style={{
                        color: (STATUS_STYLE[j.spawned_job_status || ""] || STATUS_STYLE.pending).color,
                      }}
                    >
                      {(STATUS_STYLE[j.spawned_job_status || ""] || STATUS_STYLE.pending).label}
                    </span>
                  </span>
                  {j.spawned_asset_id != null && (
                    <button
                      onClick={() => onJumpToAsset?.(j.spawned_asset_id!)}
                      className="font-medium underline"
                      style={{ color: "var(--brand-accent)" }}
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
