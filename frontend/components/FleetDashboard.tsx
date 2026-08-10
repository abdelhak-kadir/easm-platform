"use client";

import { useState, useEffect, useCallback } from "react";
import { Asset, ScanJob } from "../types/scan";
import { toolLabel } from "../lib/labels";
import StatusBadge from "./StatusBadge";
import AssetCardGrid, { type AssetHealth } from "./AssetCardGrid";
import ScanDataTable from "./ScanDataTable";

/* ── FleetJob shape ───────────────────────────────────────────────── */

interface FleetJob extends ScanJob {
  asset_id: number;
  asset_value: string;
  asset_type?: string;
}

interface StatsSnapshot {
  by_status: Record<string, number>;
  total_assets: number;
  total_scans: number;
}

/* ── Props ───────────────────────────────────────────────────────── */

type Props = {
  apiBase: string;
  assets: Asset[];
  jobs: FleetJob[];
  activeCount: number;
  onSelectAsset: (id: number) => void;
  onRefresh: () => void;
};

/* ── Component ───────────────────────────────────────────────────── */

export default function FleetDashboard({
  apiBase,
  assets,
  jobs,
  activeCount,
  onSelectAsset,
  onRefresh,
}: Props) {
  const [stats, setStats] = useState<StatsSnapshot | null>(null);

  // ── Fetch stats ───────────────────────────────────────────────
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

  // ── Cancel a job ──────────────────────────────────────────────
  function cancelJob(jobId: number) {
    fetch(`${apiBase}/scans/${jobId}/cancel`, { method: "POST" })
      .then(() => onRefresh())
      .catch(() => {});
  }

  // ── Derived data ──────────────────────────────────────────────
  // Build per-asset health from fleet jobs
  const assetHealth = new Map<number, AssetHealth>();
  for (const j of jobs) {
    const entry = assetHealth.get(j.asset_id) || {
      activeJobs: 0,
      failedCount: 0,
      completedCount: 0,
      totalJobs: 0,
      isRunning: false,
    };
    entry.totalJobs++;
    if (j.status === "running" || j.status === "pending") {
      entry.activeJobs++;
      entry.isRunning = true;
      if (!entry.lastStartedAt || (j.started_at && j.started_at > entry.lastStartedAt)) {
        entry.lastStartedAt = j.started_at;
      }
    }
    if (j.status === "failed") {
      entry.failedCount++;
    }
    if (j.status === "completed") {
      entry.completedCount++;
    }
    // Track latest tool and completion
    if (
      !entry.lastCompletedAt ||
      (j.completed_at && j.completed_at > entry.lastCompletedAt)
    ) {
      entry.lastCompletedAt = j.completed_at;
      entry.lastJobTool = j.tool;
      entry.lastJobStatus = j.status;
    }
    if (!entry.lastJobTool && j.status === "completed") {
      entry.lastJobTool = j.tool;
      entry.lastJobStatus = j.status;
    }
    assetHealth.set(j.asset_id, entry);
  }

  // KPI values
  const totalAssets = stats?.total_assets ?? assets.length;
  const activeScans =
    (stats?.by_status?.pending ?? 0) + (stats?.by_status?.running ?? 0) ||
    jobs.filter((j) => j.status === "running" || j.status === "pending").length;
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

  // ── Empty state ────────────────────────────────────────────────
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
            Cartographiez votre surface d&apos;attaque externe. Ajoutez une cible pour commencer
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

  // ── Main dashboard ────────────────────────────────────────────
  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Hero band */}
      <div
        className="rounded-xl px-6 py-6"
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
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
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

      {/* Active jobs monitor (compact) */}
      {jobs.filter((j) => j.status === "running" || j.status === "pending").length > 0 && (
        <div className="panel">
          <div
            className="px-5 py-3 flex items-center justify-between"
            style={{ borderBottom: "1px solid var(--border)" }}
          >
            <div className="flex items-center gap-2">
              <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
                En cours
              </p>
              <span className="status-dot status-dot--live" />
            </div>
            <span className="text-[11px] font-medium" style={{ color: "var(--text-secondary)" }}>
              {jobs.filter((j) => j.status === "running" || j.status === "pending").length} scan(s) actif(s)
            </span>
          </div>

          <div className="divide-y" style={{ borderColor: "var(--border)" }}>
            {jobs
              .filter((j) => j.status === "running" || j.status === "pending")
              .map((j) => {
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
                      <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
                        {toolLabel(j.tool).split(" (")[0]}
                      </span>
                    </span>
                    <StatusBadge status={j.status} pulsing className="relative z-10" />
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {/* ── Asset cards grid ──────────────────────────────────── */}
      <AssetCardGrid
        assets={assets}
        assetHealth={assetHealth}
        onSelectAsset={onSelectAsset}
      />

      {/* ── Scan activity data table ───────────────────────────── */}
      <ScanDataTable
        jobs={jobs}
        onSelectAsset={onSelectAsset}
        onSelectJob={(job) => {
          // Load results then select asset
          onSelectAsset(job.asset_id);
        }}
        onCancel={cancelJob}
      />
    </div>
  );
}
