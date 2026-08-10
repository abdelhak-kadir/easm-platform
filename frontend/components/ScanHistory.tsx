"use client";

import { useState, useEffect, useCallback } from "react";
import { Asset, ScanJob, AssetDiffResponse } from "../types/scan";
import { timeAgo, formatElapsed } from "../lib/time";
import { toolLabel } from "../lib/labels";
import StatusBadge from "./StatusBadge";
import Skeleton from "./Skeleton";

interface Props {
  apiBase: string;
  asset: Asset | null;
  onSelectJob: (job: ScanJob) => void;
  refreshKey: number;
  activeJobId?: number | null;
  onJobsLoaded?: (jobs: ScanJob[]) => void;
  onJumpToAsset?: (assetId: number) => void;
}

export default function ScanHistory({
  apiBase,
  asset,
  onSelectJob,
  refreshKey,
  activeJobId,
  onJobsLoaded,
  onJumpToAsset,
}: Props) {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(false);
  const [diffData, setDiffData] = useState<AssetDiffResponse | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);

  function fetchDiff() {
    if (!asset) return;
    setDiffLoading(true);
    fetch(`${apiBase}/scans/asset/${asset.id}/diff`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: AssetDiffResponse) => setDiffData(data))
      .catch(() => setDiffData(null))
      .finally(() => setDiffLoading(false));
  }

  const loadJobs = useCallback(() => {
    if (!asset) return;
    setLoading(true);
    fetch(`${apiBase}/scans/asset/${asset.id}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: ScanJob[]) => {
        setJobs(data);
        onJobsLoaded?.(data);
      })
      .catch(() => {
        setJobs([]);
        onJobsLoaded?.([]);
      })
      .finally(() => setLoading(false));
  }, [apiBase, asset, onJobsLoaded]);

  useEffect(() => {
    loadJobs();
  }, [loadJobs, refreshKey]);

  if (!asset) return null;

  // Group jobs by status for section headers
  const running = jobs.filter((j) => j.status === "running" || j.status === "pending");
  const completed = jobs.filter((j) => j.status === "completed");
  const failed = jobs.filter((j) => j.status === "failed");

  if (loading) {
    return (
      <div className="mb-6">
        <p className="eyebrow mb-3">Historique des analyses</p>
        <div className="panel p-4">
          <Skeleton variant="list" count={3} />
        </div>
      </div>
    );
  }

  if (jobs.length === 0) {
    return (
      <div
        className="mb-6 rounded-xl px-5 py-8 text-center"
        style={{
          background: "var(--panel)",
          border: "1px dashed var(--border)",
        }}
      >
        <p className="text-sm font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
          Aucune analyse pour cette cible
        </p>
        <p className="text-xs mb-4" style={{ color: "var(--text-secondary)" }}>
          Lancez une analyse rapide ou une découverte par vagues pour commencer.
        </p>
        <div className="text-[11px] space-y-1" style={{ color: "var(--text-secondary)" }}>
          <p>• Analyse rapide&nbsp;: exécute tous les outils applicables en une fois</p>
          <p>• Découverte&nbsp;: exploration par vagues, idéal pour les domaines racine</p>
        </div>
      </div>
    );
  }

  function renderJobRow(j: ScanJob) {
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
          {/* Tool info */}
          <span className="flex-1 flex items-center gap-2 min-w-0">
            <span className="font-semibold truncate" style={{ color: "var(--text-primary)" }}>
              {toolLabel(j.tool)}
            </span>
            {isRunning && j.started_at ? (
              <span className="text-[10px] shrink-0 tabular-nums" style={{ color: "var(--high)" }}>
                Depuis {formatElapsed(j.started_at)}
              </span>
            ) : (
              <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
                {j.completed_at ? timeAgo(j.completed_at) : "—"}
              </span>
            )}
          </span>

          <StatusBadge status={j.status} pulsing={isRunning} />

          {/* Cancel button */}
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
              Annuler
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
              <StatusBadge status={j.spawned_job_status || "pending"} />
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
  }

  return (
    <div className="mb-6">
      <p className="eyebrow mb-3">Historique des analyses</p>

      {/* ── Diff button ─────────────────────────────────── */}
      <div className="mb-3">
        {!diffData ? (
          <button
            onClick={fetchDiff}
            disabled={diffLoading}
            className="text-[10px] font-semibold uppercase px-3 py-1 rounded-full transition-colors"
            style={{
              color: "var(--brand-accent)",
              background: "var(--brand-dim)",
              border: "1px solid var(--brand-accent)",
              opacity: diffLoading ? 0.5 : 1,
            }}
          >
            {diffLoading ? "Comparaison..." : "Comparer les résultats"}
          </button>
        ) : (
          <button
            onClick={() => setDiffData(null)}
            className="text-[10px] font-semibold uppercase px-3 py-1 rounded-full transition-colors"
            style={{
              color: "var(--text-secondary)",
              background: "var(--panel-dim)",
              border: "1px solid var(--border)",
            }}
          >
            Masquer la comparaison
          </button>
        )}
      </div>

      {/* ── Diff results ─────────────────────────────────── */}
      {diffData && diffData.diffs.length === 0 && (
        <div
          className="text-xs px-4 py-3 rounded-md mb-3"
          style={{ color: "var(--text-secondary)", background: "var(--panel-dim)" }}
        >
          Aucune différence détectée — chaque outil n&apos;a qu&apos;une seule version de résultats.
        </div>
      )}
      {diffData && diffData.diffs.length > 0 && (
        <div className="space-y-3 mb-3">
          {diffData.diffs.map((d) => (
            <div
              key={d.tool}
              className="panel card-pad text-xs"
              style={{ borderLeft: "3px solid var(--brand-accent)" }}
            >
              <p className="font-bold mb-2" style={{ color: "var(--text-primary)" }}>
                {toolLabel(d.tool)}{" "}
                <span style={{ color: "var(--text-secondary)" }}>
                  v{d.previous_version} → v{d.latest_version}
                </span>
              </p>

              {d.added_keys.length > 0 && (
                <div className="mb-1">
                  <span className="font-semibold" style={{ color: "var(--success)" }}>
                    +{d.added_keys.length} nouveau{d.added_keys.length !== 1 ? "x" : ""} champ{d.added_keys.length !== 1 ? "s" : ""}:{" "}
                  </span>
                  <span style={{ color: "var(--text-secondary)" }}>{d.added_keys.join(", ")}</span>
                </div>
              )}
              {d.removed_keys.length > 0 && (
                <div className="mb-1">
                  <span className="font-semibold" style={{ color: "var(--critical)" }}>
                    −{d.removed_keys.length} champ{d.removed_keys.length !== 1 ? "s" : ""} retiré{d.removed_keys.length !== 1 ? "s" : ""}:{" "}
                  </span>
                  <span style={{ color: "var(--text-secondary)" }}>{d.removed_keys.join(", ")}</span>
                </div>
              )}
              {d.changed_keys.map((ck) => (
                <div key={ck.key} className="mb-1">
                  <span className="font-semibold" style={{ color: "var(--high)" }}>
                    ~ {ck.key}:{" "}
                  </span>
                  {ck.added_items && ck.removed_items ? (
                    <span style={{ color: "var(--text-secondary)" }}>
                      <span style={{ color: "var(--success)" }}>
                        +{ck.added_items.length}
                      </span>
                      {" / "}
                      <span style={{ color: "var(--critical)" }}>
                        −{ck.removed_items.length}
                      </span>
                      {" élément(s)"}
                    </span>
                  ) : (
                    <span style={{ color: "var(--text-secondary)" }}>
                      <span style={{ textDecoration: "line-through", color: "var(--critical)" }}>
                        {JSON.stringify(ck.old)}
                      </span>
                      {" → "}
                      <span style={{ color: "var(--success)" }}>
                        {JSON.stringify(ck.new)}
                      </span>
                    </span>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      <div className="panel divide-y" style={{ borderColor: "var(--border)" }}>
        {/* Running / pending */}
        {running.length > 0 && (
          <>
            <div
              className="px-4 py-2 text-[10px] font-semibold uppercase tracking-[0.06em] flex items-center gap-2"
              style={{ color: "var(--high)", background: "var(--high-dim)" }}
            >
              <span className="status-dot status-dot--live" />
              En cours ({running.length})
            </div>
            {running.map(renderJobRow)}
          </>
        )}

        {/* Completed */}
        {completed.length > 0 && (
          <>
            <div
              className="px-4 py-2 text-[10px] font-semibold uppercase tracking-[0.06em]"
              style={{ color: "var(--success)", background: "var(--success-dim)" }}
            >
              Terminées ({completed.length})
            </div>
            {completed.map(renderJobRow)}
          </>
        )}

        {/* Failed */}
        {failed.length > 0 && (
          <>
            <div
              className="px-4 py-2 text-[10px] font-semibold uppercase tracking-[0.06em]"
              style={{ color: "var(--critical)", background: "var(--critical-dim)" }}
            >
              Échouées ({failed.length})
            </div>
            {failed.map(renderJobRow)}
          </>
        )}
      </div>
    </div>
  );
}
