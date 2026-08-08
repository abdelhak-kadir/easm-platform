"use client";

import { useState, useEffect, useCallback } from "react";
import { Asset, ScanJob, Finding } from "../types/scan";
import { toolLabel } from "../lib/labels";
import { timeAgo, formatElapsed } from "../lib/time";
import StatusBadge from "./StatusBadge";

interface FleetJob extends ScanJob {
  asset_id: number;
  asset_value: string;
  asset_type?: string;
}

const ASSET_TYPE_LABEL: Record<string, string> = {
  domain: "Domaine",
  subdomain: "Sous-domaine",
  ip: "IP",
  email: "Email",
};

interface StatsSnapshot {
  by_status: Record<string, number>;
  total_assets: number;
  total_scans: number;
}

type Props = {
  apiBase: string;
  assets: Asset[];
  jobs: FleetJob[];
  activeCount: number;
  onSelectAsset: (id: number) => void;
  onRefresh: () => void;
};

export default function FleetDashboard({
  apiBase,
  assets,
  jobs,
  activeCount,
  onSelectAsset,
  onRefresh,
}: Props) {
  const [stats, setStats] = useState<StatsSnapshot | null>(null);
  const [expandedJobId, setExpandedJobId] = useState<number | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<Finding[]>([]);
  const [loadingResults, setLoadingResults] = useState(false);
  const [showAllActivity, setShowAllActivity] = useState(false);
  const [tick, setTick] = useState(0);

  // ── Fetch stats ─────────────────────────────────────────────────
  const fetchStats = useCallback(() => {
    fetch(`${apiBase}/scans/stats`)
      .then((r) => {
        if (!r.ok) return null;
        return r.json();
      })
      .then((data: StatsSnapshot | null) => {
        if (data) setStats(data);
      })
      .catch(() => {});
  }, [apiBase]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  // ── Live tick for elapsed timers ─────────────────────────────────
  useEffect(() => {
    const hasActive = jobs.some((j) => j.status === "running");
    if (!hasActive) return;
    const interval = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(interval);
  }, [jobs]);

  // ── Expand job results ──────────────────────────────────────────
  function toggleResults(jobId: number) {
    if (expandedJobId === jobId) {
      setExpandedJobId(null);
      setExpandedFindings([]);
      return;
    }
    setExpandedJobId(jobId);
    setLoadingResults(true);
    fetch(`${apiBase}/scans/${jobId}/results`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data) => {
        setExpandedFindings(data.findings || []);
      })
      .catch(() => {
        setExpandedFindings([]);
      })
      .finally(() => setLoadingResults(false));
  }

  // ── Cancel a job ────────────────────────────────────────────────
  function cancelJob(jobId: number) {
    fetch(`${apiBase}/scans/${jobId}/cancel`, { method: "POST" })
      .then(() => {
        onRefresh();
      })
      .catch(() => {});
  }

  // ── Derived data ────────────────────────────────────────────────
  const activeJobs = jobs.filter((j) => j.status === "running" || j.status === "pending");
  const completedJobs = jobs.filter((j) => j.status === "completed" || j.status === "failed");

  // Per-asset health summary from fleet jobs
  const assetHealth = new Map<number, { activeJobs: FleetJob[]; lastJob?: FleetJob; failedCount: number }>();
  for (const j of jobs) {
    const entry = assetHealth.get(j.asset_id) || { activeJobs: [], failedCount: 0 };
    if (j.status === "running" || j.status === "pending") {
      entry.activeJobs.push(j);
    }
    if (j.status === "failed") {
      entry.failedCount++;
    }
    if (!entry.lastJob || (j.completed_at && (!entry.lastJob.completed_at || j.completed_at > entry.lastJob.completed_at))) {
      entry.lastJob = j;
    }
    assetHealth.set(j.asset_id, entry);
  }

  // KPI values
  const totalAssets = stats?.total_assets ?? assets.length;
  const activeScans = (stats?.by_status?.pending ?? 0) + (stats?.by_status?.running ?? 0) || activeJobs.length;
  const completedTotal = stats?.by_status?.completed ?? 0;
  const failedTotal = stats?.by_status?.failed ?? 0;

  const statTiles = [
    {
      label: "Cibles",
      value: totalAssets,
      subtitle: `${assets.filter((a) => a.asset_type === "domain").length} domaines · ${assets.filter((a) => a.asset_type === "subdomain").length} sous-domaines · ${assets.filter((a) => a.asset_type === "ip").length} IPs`,
    },
    {
      label: "Scans actifs",
      value: activeScans,
      urgent: activeScans > 0,
    },
    { label: "Terminés", value: completedTotal },
    { label: "Échecs", value: failedTotal, urgent: failedTotal > 0 },
  ];

  // Activity feed
  const recentForFeed = jobs.filter((j) => j.status !== "pending").slice(0, showAllActivity ? 50 : 8);

  // ── Empty state ──────────────────────────────────────────────────
  if (assets.length === 0) {
    return (
      <div className="max-w-2xl mx-auto">
        <div
          className="rounded-xl px-8 py-10 mb-6 text-center"
          style={{ background: "var(--surface-deep)" }}
        >
          <h1
            className="text-2xl font-extrabold mb-2"
            style={{ color: "var(--text-on-dark)", fontFamily: "var(--font-manrope)" }}
          >
            Bienvenue dans EASM
          </h1>
          <p className="text-sm mb-6 max-w-md mx-auto" style={{ color: "var(--text-on-dark-soft)" }}>
            Cartographiez votre surface d'attaque externe. Ajoutez une cible pour commencer
            la découverte automatique de vos actifs exposés sur Internet.
          </p>

          <div className="grid grid-cols-3 gap-4 mb-6 text-left">
            {[
              { step: "1", title: "Ajoutez une cible", desc: "Domaine ou adresse IP dans la barre latérale gauche." },
              { step: "2", title: "Lancez une analyse", desc: "Analyse rapide pour un aperçu, ou découverte par vagues pour explorer en profondeur." },
              { step: "3", title: "Examinez les résultats", desc: "Consultez les failles, ports ouverts et actifs découverts, triés par criticité." },
            ].map((s) => (
              <div
                key={s.step}
                className="rounded-xl p-4"
                style={{ background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.10)" }}
              >
                <div
                  className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-extrabold mb-3"
                  style={{ background: "var(--brand-accent)", color: "#fff" }}
                >
                  {s.step}
                </div>
                <p className="text-sm font-bold mb-1" style={{ color: "var(--text-on-dark)" }}>
                  {s.title}
                </p>
                <p className="text-xs" style={{ color: "var(--text-on-dark-soft)" }}>
                  {s.desc}
                </p>
              </div>
            ))}
          </div>

          <button
            onClick={() => {
              const input = document.getElementById("asset-search-input");
              input?.focus();
            }}
            className="btn-white text-sm"
          >
            Ajouter votre première cible
          </button>
        </div>
      </div>
    );
  }

  // ── Main dashboard ──────────────────────────────────────────────
  return (
    <div className="max-w-5xl mx-auto">
      {/* Hero band */}
      <div
        className="rounded-xl px-6 py-6 mb-6"
        style={{ background: "var(--surface-deep)" }}
      >
        <div className="flex items-center justify-between">
          <div>
            <h1
              className="text-2xl font-extrabold mb-1"
              style={{ color: "var(--text-on-dark)", fontFamily: "var(--font-manrope)" }}
            >
              Tableau de bord
            </h1>
            <p className="text-sm max-w-lg" style={{ color: "var(--text-on-dark-soft)" }}>
              Surveillez votre surface d&apos;attaque externe.
            </p>
          </div>
          <button onClick={onRefresh} className="btn-outline-light text-sm">
            Actualiser
          </button>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {statTiles.map((t) => (
          <div key={t.label} className="panel card-pad">
            <p
              className="text-3xl font-extrabold tabular-nums tracking-tight"
              style={{
                color: t.urgent ? "var(--critical)" : "var(--text-primary)",
                fontFamily: "var(--font-manrope)",
              }}
            >
              {t.value}
            </p>
            <p
              className="text-[11px] font-semibold uppercase tracking-[0.06em] mt-1"
              style={{ color: "var(--text-secondary)" }}
            >
              {t.label}
            </p>
            {t.subtitle && (
              <p className="text-[11px] mt-1" style={{ color: "var(--text-secondary)" }}>
                {t.subtitle}
              </p>
            )}
          </div>
        ))}
      </div>

      {/* ── Asset grid ────────────────────────────────────────────── */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-3">
          <p className="eyebrow">Vos cibles</p>
          <span className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
            {assets.length} cible{assets.length !== 1 ? "s" : ""}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {assets.map((a) => {
            const health = assetHealth.get(a.id);
            const hasActive = (health?.activeJobs.length ?? 0) > 0;
            const hasFailed = (health?.failedCount ?? 0) > 0;
            const lastJob = health?.lastJob;

            // Left border color
            let borderColor = "var(--border)";
            if (hasActive) borderColor = "var(--brand-accent)";
            else if (hasFailed) borderColor = "var(--critical)";
            else if (a.status === "done") borderColor = "var(--success)";
            else borderColor = "var(--text-secondary)";

            return (
              <button
                key={a.id}
                onClick={() => onSelectAsset(a.id)}
                className="panel card-pad text-left transition-all hover:shadow-[var(--shadow-elevated)] cursor-pointer"
                style={{ borderLeft: `3px solid ${borderColor}` }}
              >
                <div className="flex items-center gap-2 mb-2">
                  <span className="mono text-sm font-semibold truncate flex-1" style={{ color: "var(--text-primary)" }}>
                    {a.value}
                  </span>
                  <span
                    className="text-[10px] font-medium uppercase px-1.5 py-0.5 rounded shrink-0"
                    style={{
                      color: "var(--brand-accent)",
                      background: "var(--brand-dim)",
                    }}
                  >
                    {ASSET_TYPE_LABEL[a.asset_type] || a.asset_type}
                  </span>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  {hasActive ? (
                    <span className="flex items-center gap-1 text-[11px]" style={{ color: "var(--brand-accent)" }}>
                      <span className="status-dot status-dot--live" />
                      {health!.activeJobs.length} scan{health!.activeJobs.length !== 1 ? "s" : ""} actif{health!.activeJobs.length !== 1 ? "s" : ""}
                    </span>
                  ) : lastJob ? (
                    <span className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
                      Dernier scan&nbsp;: {toolLabel(lastJob.tool)} · {lastJob.completed_at ? timeAgo(lastJob.completed_at) : "—"}
                    </span>
                  ) : (
                    <span className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
                      Aucun scan
                    </span>
                  )}

                  {hasFailed && (
                    <span
                      className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full"
                      style={{ color: "var(--critical)", background: "var(--critical-dim)" }}
                    >
                      {health!.failedCount} échec{health!.failedCount !== 1 ? "s" : ""}
                    </span>
                  )}
                </div>

                {lastJob && lastJob.status === "running" && lastJob.started_at && (
                  <p className="text-[10px] mt-1 tabular-nums" style={{ color: "var(--high)" }}>
                    Depuis {formatElapsed(lastJob.started_at)}
                  </p>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Active jobs monitor ───────────────────────────────────── */}
      {activeJobs.length > 0 && (
        <div className="panel mb-6">
          <div
            className="px-5 py-3 flex items-center justify-between"
            style={{ borderBottom: "1px solid var(--border)" }}
          >
            <div className="flex items-center gap-2">
              <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
                En cours
              </p>
              <span className="status-dot status-dot--live" title={`${activeJobs.length} scan(s) actif(s)`} />
            </div>
            <span className="text-[11px] font-medium" style={{ color: "var(--text-secondary)" }}>
              {activeJobs.length} scan{activeJobs.length !== 1 ? "s" : ""} actif{activeJobs.length !== 1 ? "s" : ""}
            </span>
          </div>

          <div className="divide-y" style={{ borderColor: "var(--border)" }}>
            {activeJobs.map((j) => {
              const isRunning = j.status === "running";
              return (
                <div
                  key={j.id}
                  className="flex items-center gap-3 px-5 py-3"
                  style={{ position: "relative", overflow: "hidden" }}
                >
                  {isRunning && <div className="scan-sweep" style={{ position: "absolute", inset: 0 }} />}
                  <span className="flex-1 min-w-0 flex items-center gap-2 relative z-10">
                    <button
                      onClick={() => onSelectAsset(j.asset_id)}
                      className="text-sm font-semibold truncate hover:underline"
                      style={{ color: "var(--text-primary)" }}
                    >
                      {j.asset_value}
                    </button>
                    {j.asset_type && (
                      <span
                        className="text-[10px] font-medium uppercase px-1.5 py-0.5 rounded shrink-0"
                        style={{ color: "var(--brand-accent)", background: "var(--brand-dim)" }}
                      >
                        {ASSET_TYPE_LABEL[j.asset_type] || j.asset_type}
                      </span>
                    )}
                    <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
                      {toolLabel(j.tool)}
                    </span>
                    {isRunning && j.started_at && (
                      <span className="text-[10px] shrink-0 tabular-nums" style={{ color: "var(--text-secondary)" }}>
                        Depuis {formatElapsed(j.started_at)}
                      </span>
                    )}
                  </span>

                  <StatusBadge status={j.status} pulsing className="relative z-10" />

                  <span
                    role="button"
                    tabIndex={0}
                    onClick={(e) => { e.stopPropagation(); cancelJob(j.id); }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") { e.stopPropagation(); cancelJob(j.id); }
                    }}
                    className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full shrink-0 transition-colors cursor-pointer relative z-10"
                    style={{
                      color: "var(--critical)",
                      background: "var(--critical-dim)",
                      border: "1px solid var(--critical)",
                    }}
                    title="Annuler cette analyse"
                  >
                    Annuler
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Recent activity feed ──────────────────────────────────── */}
      <div className="panel">
        <div
          className="px-5 py-3 flex items-center justify-between"
          style={{ borderBottom: "1px solid var(--border)" }}
        >
          <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
            Activité récente
          </p>
          <span className="text-[11px] font-medium" style={{ color: "var(--text-secondary)" }}>
            {jobs.length} scan{jobs.length !== 1 ? "s" : ""}
          </span>
        </div>

        {recentForFeed.length === 0 ? (
          <p className="px-5 py-8 text-sm text-center" style={{ color: "var(--text-secondary)" }}>
            Aucune activité récente.
          </p>
        ) : (
          <>
            <div className="divide-y" style={{ borderColor: "var(--border)" }}>
              {recentForFeed.map((j) => {
                const isExpanded = expandedJobId === j.id;
                return (
                  <div key={j.id}>
                    <div
                      className="w-full text-left px-5 py-3 flex items-center gap-3 transition-colors hover:bg-[var(--panel-dim)] cursor-pointer"
                      onClick={() => {
                        if (j.status === "completed") toggleResults(j.id);
                      }}
                    >
                      <span className="flex-1 min-w-0 flex items-center gap-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); onSelectAsset(j.asset_id); }}
                          className="text-sm font-semibold truncate hover:underline"
                          style={{ color: "var(--text-primary)" }}
                        >
                          {j.asset_value}
                        </button>
                        <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
                          {toolLabel(j.tool)}
                        </span>
                      </span>
                      <span className="text-[11px] shrink-0" style={{ color: "var(--text-secondary)" }}>
                        {j.completed_at ? timeAgo(j.completed_at) : "—"}
                      </span>
                      <StatusBadge status={j.status} />
                      {j.status === "completed" && (
                        <span className="text-[10px] shrink-0" style={{ color: "var(--brand-accent)" }}>
                          {isExpanded ? "▴" : "▾"}
                        </span>
                      )}
                    </div>

                    {isExpanded && (
                      <div className="px-5 pb-4 ml-4" style={{ borderTop: "1px solid var(--border)" }}>
                        {loadingResults ? (
                          <p className="text-xs py-3" style={{ color: "var(--text-secondary)" }}>
                            Chargement des résultats…
                          </p>
                        ) : expandedFindings.length === 0 ? (
                          <p className="text-xs py-3" style={{ color: "var(--text-secondary)" }}>
                            Aucun résultat pour cette analyse.
                          </p>
                        ) : (
                          <div className="pt-3 space-y-2">
                            {expandedFindings.map((f) => {
                              const sevColor =
                                f.severity === "critical" || f.severity === "high"
                                  ? "var(--critical)"
                                  : f.severity === "medium"
                                  ? "var(--high)"
                                  : "var(--text-secondary)";
                              return (
                                <div
                                  key={f.id}
                                  className="text-xs flex items-start gap-2 py-1.5 px-3 rounded-md"
                                  style={{ background: "var(--panel-dim)" }}
                                >
                                  <span className="font-semibold uppercase shrink-0 mt-px" style={{ color: sevColor }}>
                                    {f.severity}
                                  </span>
                                  <span style={{ color: "var(--text-primary)" }}>{f.title}</span>
                                  <span className="shrink-0" style={{ color: "var(--text-secondary)" }}>
                                    [{f.finding_type}]
                                  </span>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {!showAllActivity && jobs.filter((j) => j.status !== "pending").length > 8 && (
              <div className="px-5 py-3 text-center" style={{ borderTop: "1px solid var(--border)" }}>
                <button
                  onClick={() => setShowAllActivity(true)}
                  className="text-xs font-medium"
                  style={{ color: "var(--brand-accent)" }}
                >
                  Voir tout ({jobs.filter((j) => j.status !== "pending").length})
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
