"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Asset,
  ScanJob,
  AssetDashboardResponse,
  DashboardToolSummary,
  RelatedAssetGroup,
} from "../types/scan";
import { toolLabel } from "../lib/labels";
import { timeAgo, formatElapsed } from "../lib/time";
import StatusBadge from "./StatusBadge";
import Skeleton from "./Skeleton";
import TopologyMap from "./TopologyMap";
import ToolCategoryGroup from "./ToolCategoryGroup";

const ASSET_TYPE_LABEL: Record<string, string> = {
  domain: "Domaine",
  subdomain: "Sous-domaine",
  ip: "IP",
  email: "Email",
};

const RELATION_LABEL: Record<string, string> = {
  child: "découvert via cette cible",
  parent: "a découvert cette cible",
  both: "liens réciproques",
};

interface Props {
  apiBase: string;
  asset: Asset;
  refreshKey: number;
  onSelectJob: (job: ScanJob) => void;
  onJumpToAsset: (assetId: number) => void;
  onJobsLoaded: (jobs: ScanJob[]) => void;
}

export default function AssetDashboard({
  apiBase,
  asset,
  refreshKey,
  onSelectJob,
  onJumpToAsset,
  onJobsLoaded,
}: Props) {
  const [data, setData] = useState<AssetDashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const busy = data
    ? data.scans.some((j) => j.status === "pending" || j.status === "running")
    : false;

  const load = useCallback(() => {
    fetch(`${apiBase}/assets/${asset.id}/dashboard`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((json: AssetDashboardResponse) => {
        setData(json);
        onJobsLoaded(json.scans);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [apiBase, asset.id, onJobsLoaded]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load, refreshKey]);

  // Poll while any job is active
  useEffect(() => {
    if (!busy) return;
    const interval = setInterval(load, 2000);
    return () => clearInterval(interval);
  }, [busy, load]);

  // ── Quick actions ──────────────────────────────────────────────────

  function cancelJob(jobId: number) {
    fetch(`${apiBase}/scans/${jobId}/cancel`, { method: "POST" }).then(() => load());
  }

  function runSingleTool(tool: string) {
    if (!asset) return;
    fetch(`${apiBase}/scans/${tool}/${asset.id}`, { method: "POST" }).then(() => {
      setLoading(true);
      load();
    });
  }

  // ── Loading ────────────────────────────────────────────────────────

  if (loading && !data) {
    return (
      <div className="space-y-4">
        <div className="panel p-4">
          <Skeleton variant="list" count={3} />
        </div>
      </div>
    );
  }

  // ── Error ──────────────────────────────────────────────────────────

  if (error && !data) {
    return (
      <div
        className="rounded-xl px-5 py-8 text-center"
        style={{ background: "var(--panel)", border: "1px dashed var(--border)" }}
      >
        <p className="text-sm font-semibold mb-1" style={{ color: "var(--critical)" }}>
          Impossible de charger le tableau de bord
        </p>
        <p className="text-xs mb-4" style={{ color: "var(--text-secondary)" }}>
          {error}
        </p>
        <button onClick={load} className="btn-primary text-sm">
          Réessayer
        </button>
      </div>
    );
  }

  if (!data) return null;

  const { risk, tool_summary, related_assets } = data;

  // ── Risk strip ─────────────────────────────────────────────────────

  const totalFindings = risk?.finding_count ?? 0;

  return (
    <div className="space-y-5">
      {/* ── Topology map (scan chain visualization) ────────────────── */}
      <TopologyMap
        asset={asset}
        toolSummary={data.tool_summary}
        relatedAssets={data.related_assets}
        onSelectJob={onSelectJob}
        onJumpToAsset={onJumpToAsset}
      />

      {/* ── Risk strip ──────────────────────────────────────────────── */}
      {totalFindings > 0 && risk && (
        <div className="panel card-pad">
          <p className="eyebrow mb-3">Sévérités détectées</p>
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex flex-wrap gap-1.5">
              {(["critical", "high", "medium", "low", "info"] as const).map((s) => {
                const n = risk.breakdown[s] ?? 0;
                if (!n) return null;
                return (
                  <span key={s} className="severity-pill text-[11px]">
                    {n} <span className="uppercase text-[10px]">{s}</span>
                  </span>
                );
              })}
            </div>
            <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
              {risk.cve_count > 0 && `${risk.cve_count} CVE · `}
              {risk.exposed_ports > 0 && `${risk.exposed_ports} ports · `}
              {totalFindings} trouvaille{totalFindings !== 1 ? "s" : ""}
              {risk.last_scan && (
                <> · Dernier scan {timeAgo(risk.last_scan)}</>
              )}
            </span>
          </div>
        </div>
      )}

      {/* ── Related assets bar ──────────────────────────────────────── */}
      {related_assets.length > 0 && (
        <div className="panel card-pad">
          <p className="eyebrow mb-2">Actifs liés</p>
          <div className="flex flex-wrap gap-2">
            {related_assets.map((rel) => (
              <RelatedAssetChip
                key={rel.asset.id}
                group={rel}
                onJump={() => onJumpToAsset(rel.asset.id)}
              />
            ))}
          </div>
        </div>
      )}

      {/* ── Tools grouped by category ───────────────────────────────── */}
      {(() => {
        const grouped: Record<string, DashboardToolSummary[]> = {};
        for (const ts of tool_summary) {
          const cat = ts.category || "other";
          if (!grouped[cat]) grouped[cat] = [];
          grouped[cat].push(ts);
        }
        return Object.entries(grouped).map(([cat, tools]) => (
          <ToolCategoryGroup
            key={cat}
            category={cat}
            tools={tools}
            onSelectJob={onSelectJob}
            onRunTool={runSingleTool}
          />
        ));
      })()}

      {/* ── Related assets detail ───────────────────────────────────── */}
      {related_assets.map((rel) => (
        <RelatedAssetSection
          key={rel.asset.id}
          group={rel}
          apiBase={apiBase}
          onJump={() => onJumpToAsset(rel.asset.id)}
          onSelectJob={onSelectJob}
          onCancel={cancelJob}
        />
      ))}
    </div>
  );
}

/* ── Related asset chip (inline bar) ─────────────────────────────────── */

function RelatedAssetChip({
  group,
  onJump,
}: {
  group: RelatedAssetGroup;
  onJump: () => void;
}) {
  const typeLabel = ASSET_TYPE_LABEL[group.asset.asset_type] || group.asset.asset_type;
  return (
    <button
      onClick={onJump}
      className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md transition-colors hover:opacity-80"
      style={{
        background: "var(--brand-dim)",
        border: "1px solid var(--brand-accent)",
        color: "var(--brand-accent)",
      }}
    >
      <span className="mono font-semibold">{group.asset.value}</span>
      <span className="opacity-60">·</span>
      <span>{typeLabel}</span>
      {group.summary.latest_status && (
        <>
          <span className="opacity-60">·</span>
          <StatusBadge status={group.summary.latest_status} />
        </>
      )}
    </button>
  );
}

/* ── Single tool card ────────────────────────────────────────────────── */

function ToolCard({
  summary,
  onSelectJob,
  onCancel,
  onRun,
}: {
  summary: DashboardToolSummary;
  onSelectJob: (job: ScanJob) => void;
  onCancel: (jobId: number) => void;
  onRun: (tool: string) => void;
}) {
  const { tool, latest_job, latest_status, job_count, finding_count, severities, last_completed_at, applicable } = summary;
  const isActive = latest_status === "pending" || latest_status === "running";
  const isCompleted = latest_status === "completed";
  const isFailed = latest_status === "failed";
  const hasRun = latest_job !== null;

  const accent = isActive
    ? "var(--high)"
    : isFailed
      ? "var(--critical)"
      : isCompleted
        ? "var(--success)"
        : "var(--border)";

  return (
    <div
      className="panel overflow-hidden"
      style={{ borderLeft: `3px solid ${accent}` }}
    >
      {/* Header */}
      <div className="px-4 py-3 flex items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-semibold truncate" style={{ color: "var(--text-primary)" }}>
            {toolLabel(tool)}
          </p>
          {hasRun ? (
            <p className="text-[11px] mt-0.5" style={{ color: "var(--text-secondary)" }}>
              {job_count} scan{job_count !== 1 ? "s" : ""}
              {last_completed_at && <> · {timeAgo(last_completed_at)}</>}
            </p>
          ) : (
            <p className="text-[11px] mt-0.5" style={{ color: "var(--text-secondary)" }}>
              {applicable ? "Disponible" : "Non applicable"}
            </p>
          )}
        </div>
        {latest_status && <StatusBadge status={latest_status} pulsing={isActive} />}
        {!hasRun && applicable && (
          <span className="text-[10px] uppercase font-semibold" style={{ color: "var(--text-secondary)" }}>
            Prêt
          </span>
        )}
      </div>

      {/* Severity counts */}
      {isCompleted && finding_count > 0 && (
        <div
          className="px-4 py-2 flex flex-wrap gap-1.5"
          style={{ borderTop: "1px solid var(--border)" }}
        >
          {(["critical", "high", "medium", "low", "info"] as const).map((s) => {
            const n = severities[s] ?? 0;
            if (!n) return null;
            return (
              <span key={s} className="severity-pill text-[10px]">
                {n} <span className="uppercase">{s.slice(0, 3)}</span>
              </span>
            );
          })}
        </div>
      )}

      {/* Actions */}
      <div
        className="px-4 py-2 flex items-center gap-2"
        style={{ borderTop: "1px solid var(--border)" }}
      >
        {isCompleted && (
          <button
            onClick={() => latest_job && onSelectJob(latest_job)}
            className="text-[11px] font-semibold uppercase tracking-[0.04em] transition-colors hover:underline"
            style={{ color: "var(--brand-accent)" }}
          >
            Voir les résultats
          </button>
        )}
        {isActive && latest_job && (
          <button
            onClick={() => onCancel(latest_job.id)}
            className="text-[11px] font-semibold uppercase tracking-[0.04em] transition-colors hover:underline"
            style={{ color: "var(--critical)" }}
          >
            Annuler
          </button>
        )}
        {!hasRun && applicable && (
          <button
            onClick={() => onRun(tool)}
            className="text-[11px] font-semibold uppercase tracking-[0.04em] transition-colors hover:underline"
            style={{ color: "var(--brand-accent)" }}
          >
            Lancer
          </button>
        )}
        {(isCompleted || isFailed || !applicable) && !isActive && (
          <button
            onClick={() => onRun(tool)}
            className="text-[11px] font-semibold uppercase tracking-[0.04em] transition-colors hover:underline"
            style={{ color: "var(--text-secondary)" }}
          >
            Relancer
          </button>
        )}
      </div>
    </div>
  );
}

/* ── Related asset detail section ────────────────────────────────────── */

function RelatedAssetSection({
  group,
  apiBase: _apiBase,
  onJump,
  onSelectJob,
  onCancel,
}: {
  group: RelatedAssetGroup;
  apiBase: string;
  onJump: () => void;
  onSelectJob: (job: ScanJob) => void;
  onCancel: (jobId: number) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const typeLabel = ASSET_TYPE_LABEL[group.asset.asset_type] || group.asset.asset_type;
  const relationLabel = RELATION_LABEL[group.relation] || group.relation;
  const { summary, scans, links } = group;

  const sevs = summary.severities || {};
  const hasFindings = summary.finding_count > 0;

  return (
    <div className="panel overflow-hidden" style={{ border: "1px solid var(--border)" }}>
      {/* Collapsed header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left px-4 py-3 flex items-center justify-between gap-3 transition-colors hover:bg-[var(--panel-dim)]"
      >
        <div className="flex items-center gap-2 min-w-0 flex-wrap">
          <span className="text-sm font-semibold mono" style={{ color: "var(--text-primary)" }}>
            {group.asset.value}
          </span>
          <span
            className="text-[10px] uppercase tracking-[0.04em] px-1.5 py-0.5 rounded"
            style={{ color: "var(--text-secondary)", background: "var(--panel-dim)" }}
          >
            {typeLabel}
          </span>
          <span className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
            · {relationLabel}
          </span>
          {summary.latest_status && (
            <StatusBadge status={summary.latest_status} />
          )}
          {hasFindings && (
            <span className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
              · {summary.finding_count} trouvaille{summary.finding_count !== 1 ? "s" : ""}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={(e) => {
              e.stopPropagation();
              onJump();
            }}
            className="text-[11px] font-semibold uppercase tracking-[0.04em] transition-colors hover:underline"
            style={{ color: "var(--brand-accent)" }}
          >
            Voir
          </button>
          <span
            style={{
              transform: expanded ? "rotate(180deg)" : "rotate(0deg)",
              transition: "transform 0.2s ease",
              fontSize: "10px",
              color: "var(--text-secondary)",
            }}
          >
            ▼
          </span>
        </div>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ borderTop: "1px solid var(--border)" }}>
          {/* Chain links */}
          {links.length > 0 && (
            <div className="px-4 py-2 space-y-1">
              {links.map((link) => (
                <div
                  key={link.id}
                  className="text-[11px] flex items-center gap-1.5"
                  style={{ color: "var(--text-secondary)" }}
                >
                  <span style={{ color: "var(--brand-accent)" }}>→</span>
                  <span className="mono">{link.spawned_asset_value || "?"}</span>
                  <span>·</span>
                  <span>{toolLabel(link.spawned_job_tool || link.tool)}</span>
                  <StatusBadge status={link.spawned_job_status || link.status} />
                </div>
              ))}
            </div>
          )}

          {/* Compact scan list */}
          {scans.length > 0 ? (
            <div className="divide-y" style={{ borderColor: "var(--border)" }}>
              {scans.map((job) => {
                const isActive = job.status === "running" || job.status === "pending";
                return (
                  <div
                    key={job.id}
                    className="px-4 py-2 flex items-center gap-3 text-sm"
                  >
                    <button
                      onClick={() => onSelectJob(job)}
                      className="flex-1 text-left truncate font-medium transition-colors hover:underline"
                      style={{ color: "var(--text-primary)" }}
                    >
                      {toolLabel(job.tool)}
                    </button>
                    <StatusBadge status={job.status} pulsing={isActive} />
                    {isActive && (
                      <button
                        onClick={() => onCancel(job.id)}
                        className="text-[10px] font-semibold uppercase"
                        style={{ color: "var(--critical)" }}
                      >
                        Annuler
                      </button>
                    )}
                    {job.status === "completed" && (
                      <button
                        onClick={() => onSelectJob(job)}
                        className="text-[10px] font-semibold uppercase"
                        style={{ color: "var(--brand-accent)" }}
                      >
                        Voir
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="px-4 py-3 text-xs" style={{ color: "var(--text-secondary)" }}>
              Aucune analyse pour cet actif.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
