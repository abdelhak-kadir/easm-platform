"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import { Asset, ScanJob, DashboardToolSummary, AssetDashboardResponse } from "../types/scan";
import { toolLabel } from "../lib/labels";
import { categoryInfo } from "../lib/categories";
import StatusBadge from "./StatusBadge";
import TopologyMap from "./TopologyMap";
import Skeleton from "./Skeleton";

/* ── Props ─────────────────────────────────────────────────────── */

interface Props {
  apiBase: string;
  asset: Asset;
  refreshKey: number;
  onSelectJob: (job: ScanJob) => void;
  onJumpToAsset: (id: number) => void;
  onJobsLoaded: (jobs: ScanJob[]) => void;
  onBackToDashboard: () => void;
}

/* ── Component ─────────────────────────────────────────────────── */

export default function DiscoveryDashboard({
  apiBase,
  asset,
  refreshKey,
  onSelectJob,
  onJumpToAsset,
  onJobsLoaded,
  onBackToDashboard,
}: Props) {
  const [data, setData] = useState<AssetDashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    fetch(`${apiBase}/assets/${asset.id}/dashboard`)
      .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then((json: AssetDashboardResponse) => {
        setData(json);
        if (json.scans) onJobsLoaded(json.scans);
      })
      .catch(() => { setLoading(false); })
      .finally(() => setLoading(false));
  }, [apiBase, asset.id, onJobsLoaded]);

  useEffect(() => { setLoading(true); load(); }, [load, refreshKey]);

  const busy = data ? data.scans.some((j) => j.status === "running" || j.status === "pending") : false;
  useEffect(() => { if (!busy) return; const i = setInterval(load, 2000); return () => clearInterval(i); }, [busy, load]);

  const [tick, setTick] = useState(0);

  function runSingleTool(tool: string) {
    fetch(`${apiBase}/scans/${tool}/${asset.id}`, { method: "POST" }).then(() => { setLoading(true); load(); });
  }

  // Hooks must be called before any conditional return
  const scanning = data?.scans ? data.scans.some((j: ScanJob) => j.status === "running" || j.status === "pending") : false;
  useEffect(() => { if (!scanning) return; const i = setInterval(() => setTick((t) => t + 1), 1000); return () => clearInterval(i); }, [scanning]);

  const grouped: Record<string, DashboardToolSummary[]> = useMemo(() => {
    const g: Record<string, DashboardToolSummary[]> = {};
    if (!data) return g;
    for (const ts of data.tool_summary) {
      const cat = ts.category || "other";
      if (!g[cat]) g[cat] = [];
      g[cat].push(ts);
    }
    return g;
  }, [data]);

  if (loading && !data) return <div className="panel p-4"><Skeleton variant="list" count={5} /></div>;
  if (!data) return null;

  const { risk, tool_summary, related_assets } = data;

  const total = tool_summary.length;
  const done = tool_summary.filter((t) => t.latest_status === "completed" || t.latest_status === "completed_no_data" || t.latest_status === "failed").length;
  const running = tool_summary.filter((t) => t.latest_status === "running" || t.latest_status === "pending").length;
  const failed = tool_summary.filter((t) => t.latest_status === "failed").length;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;

  const score = risk?.score ?? 0;
  const scoreColor = score >= 70 ? "var(--critical)" : score >= 40 ? "var(--high)" : "var(--success)";

  return (
    <div className="max-w-5xl mx-auto space-y-4">
      {/* ── Hero band ──────────────────────────────────────────── */}
      <div className="panel overflow-hidden" style={{ position: "relative" }}>
        {scanning && <div className="scan-sweep" style={{ position: "absolute", inset: 0, zIndex: 0 }} />}
        <div style={{ position: "relative", zIndex: 1, padding: "20px 24px" }}>
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div>
              <button onClick={onBackToDashboard} className="text-xs font-semibold mb-2 flex items-center gap-1 hover:underline" style={{ color: "var(--text-secondary)" }}>
                ← Tableau de bord
              </button>
              <p className="eyebrow mb-1">Cible analysée</p>
              <div className="flex items-center gap-3 flex-wrap">
                <p className="mono text-xl font-bold" style={{ color: "var(--text-primary)" }}>{asset.value}</p>
                <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full" style={{
                  color: scanning ? "var(--high)" : "var(--success)",
                  background: scanning ? "var(--high-dim)" : "var(--success-dim)",
                }}>
                  {scanning ? "● En cours" : "● Terminé"}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-4">
              {/* Score ring */}
              <div style={{ position: "relative", width: 64, height: 64 }}>
                <svg width="64" height="64" viewBox="0 0 64 64" style={{ transform: "rotate(-90deg)" }}>
                  <circle cx="32" cy="32" r="26" fill="none" stroke="var(--border)" strokeWidth="5" />
                  <circle cx="32" cy="32" r="26" fill="none" stroke={scoreColor} strokeWidth="5" strokeLinecap="round"
                    strokeDasharray={163.4} strokeDashoffset={163.4 * (1 - score / 100)}
                    style={{ transition: "stroke-dashoffset 0.6s ease" }} />
                </svg>
                <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                  <span className="text-sm font-extrabold tabular-nums" style={{ color: scoreColor, fontFamily: "var(--font-manrope)" }}>{score}</span>
                  <span className="text-[8px] uppercase" style={{ color: "var(--text-secondary)" }}>/100</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── KPI strip ──────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-2">
        {[
          { label: "Modules", value: total, color: "var(--text-primary)" },
          { label: "Terminés", value: done, color: "var(--success)" },
          { label: "En cours", value: running, color: "var(--high)" },
          { label: "Échecs", value: failed, color: failed > 0 ? "var(--critical)" : "var(--text-primary)" },
        ].map((k) => (
          <div key={k.label} className="panel card-pad text-center">
            <p className="text-2xl font-extrabold tabular-nums" style={{ color: k.color, fontFamily: "var(--font-manrope)" }}>{k.value}</p>
            <p className="text-[10px] font-semibold uppercase tracking-[0.06em] mt-1" style={{ color: "var(--text-secondary)" }}>{k.label}</p>
          </div>
        ))}
      </div>

      {/* Progress bar */}
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${pct}%`, transition: "width 0.5s ease" }} />
      </div>

      {/* ── Topology ───────────────────────────────────────────── */}
      <TopologyMap asset={asset} toolSummary={tool_summary} relatedAssets={related_assets} onSelectJob={onSelectJob} onJumpToAsset={onJumpToAsset} />

      {/* ── Modules by category ────────────────────────────────── */}
      {Object.entries(grouped).map(([cat, tools]) => {
        const info = categoryInfo(cat);
        const catDone = tools.filter((t) => t.latest_status === "completed" || t.latest_status === "completed_no_data" || t.latest_status === "failed").length;
        const catRunning = tools.filter((t) => t.latest_status === "running" || t.latest_status === "pending").length;

        return (
          <div key={cat} className="panel overflow-hidden">
            <div className="px-4 py-3 flex items-center justify-between" style={{ background: info.bgColor, borderBottom: "1px solid var(--border)" }}>
              <div className="flex items-center gap-2">
                <span style={{ fontSize: "16px" }}>{info.emoji}</span>
                <span className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>{info.label}</span>
              </div>
              <div className="flex items-center gap-2">
                {catRunning > 0 && <span className="status-dot status-dot--live" />}
                <span className="text-[10px] font-medium" style={{ color: "var(--text-secondary)" }}>
                  {catDone}/{tools.length}
                </span>
              </div>
            </div>
            <div className="divide-y" style={{ borderColor: "var(--border)" }}>
              {tools.map((ts) => {
                const isActive = ts.latest_status === "pending" || ts.latest_status === "running";
                const isDone = ts.latest_status === "completed";
                const isFailed = ts.latest_status === "failed";
                const hasRun = ts.latest_job !== null;
                const accent = isActive ? "var(--high)" : isFailed ? "var(--critical)" : isDone && ts.finding_count > 0 ? "var(--success)" : "var(--border)";

                return (
                  <div key={ts.tool} className="flex items-center gap-3 px-4 py-2.5" style={{ borderLeft: `3px solid ${accent}` }}>
                    <button onClick={() => ts.latest_job && onSelectJob(ts.latest_job)} className="flex-1 text-left text-sm font-medium truncate hover:underline"
                      style={{ color: "var(--text-primary)", cursor: ts.latest_job ? "pointer" : "default" }}>
                      {toolLabel(ts.tool).split(" (")[0]}
                    </button>
                    {ts.latest_status && <StatusBadge status={ts.latest_status} pulsing={isActive} />}
                    {isDone && ts.finding_count > 0 && (
                      <span className="text-[10px] tabular-nums font-bold px-1.5 py-0.5 rounded" style={{ color: "var(--success)", background: "var(--success-dim)" }}>
                        {ts.finding_count}
                      </span>
                    )}
                    {!hasRun && ts.applicable && (
                      <button onClick={() => runSingleTool(ts.tool)} className="text-[10px] font-semibold uppercase hover:underline" style={{ color: "var(--brand-accent)" }}>Lancer</button>
                    )}
                    {(isDone || isFailed || !ts.applicable) && !isActive && (
                      <button onClick={() => runSingleTool(ts.tool)} className="text-[10px] font-semibold uppercase hover:underline" style={{ color: "var(--text-secondary)" }}>Relancer</button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
