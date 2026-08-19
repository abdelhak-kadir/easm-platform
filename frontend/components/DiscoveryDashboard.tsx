"use client";

import { useState, useEffect, useMemo, useCallback, useRef } from "react";
import { Asset, ScanJob, DashboardToolSummary, AssetDashboardResponse } from "../types/scan";
import { toolLabel } from "../lib/labels";
import { categoryInfo } from "../lib/categories";
import StatusBadge from "./StatusBadge";
import TopologyMap from "./TopologyMap";
import Skeleton from "./Skeleton";
import DomainReputation from "./DomainReputation";

/* ── Props ─────────────────────────────────────────────────────── */

interface Props {
  apiBase: string;
  asset: Asset;
  refreshKey: number;
  onSelectJob: (job: ScanJob) => void;
  onJumpToAsset: (id: number) => void;
  onJobsLoaded: (jobs: ScanJob[]) => void;
  onToolSummary: (summary: DashboardToolSummary[]) => void;
  onBackToDashboard: () => void;
}

/* ── Component ─────────────────────────────────────────────────── */

export default function DiscoveryDashboard({
  apiBase, asset, refreshKey, onSelectJob, onJumpToAsset, onJobsLoaded, onToolSummary, onBackToDashboard,
}: Props) {
  // ── ALL hooks first ──────────────────────────────────────────
  const [data, setData] = useState<AssetDashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [topoExpanded, setTopoExpanded] = useState(false);
  const categoryRefs = useRef<Record<string, HTMLDivElement | null>>({});

  const load = useCallback(() => {
    fetch(`${apiBase}/assets/${asset.id}/dashboard`)
      .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then((json: AssetDashboardResponse) => { setData(json); setError(null); })
      .catch((e) => { setError(e.message); })
      .finally(() => setLoading(false));
  }, [apiBase, asset.id]);

  useEffect(() => { setLoading(true); load(); }, [load, refreshKey]);

  const busy = !!(data?.scans?.some((j) => j.status === "running" || j.status === "pending"));
  useEffect(() => { if (!busy) return; const i = setInterval(load, 2000); return () => clearInterval(i); }, [busy, load]);

  // Call back to parent with jobs
  useEffect(() => { if (data?.scans) onJobsLoaded(data.scans); }, [data?.scans, onJobsLoaded]);

  // Call back to parent with the tool summary (PreReport's X/Y outils counter)
  useEffect(() => { if (data?.tool_summary) onToolSummary(data.tool_summary); }, [data?.tool_summary, onToolSummary]);

  function runTool(tool: string) {
    fetch(`${apiBase}/scans/${tool}/${asset.id}`, { method: "POST" }).then(() => { setLoading(true); load(); });
  }
  function cancelJob(jobId: number) {
    fetch(`${apiBase}/scans/${jobId}/cancel`, { method: "POST" }).then(() => load());
  }
  function scrollToCategory(cat: string) {
    const el = categoryRefs.current[cat];
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // Group tools by category
  const grouped = useMemo(() => {
    const g: Record<string, DashboardToolSummary[]> = {};
    if (!data) return g;
    for (const ts of data.tool_summary) {
      const cat = ts.category || "other";
      (g[cat] ??= []).push(ts);
    }
    return g;
  }, [data]);

  // ── Render ───────────────────────────────────────────────────
  if (loading && !data) return <div className="panel p-4"><Skeleton variant="list" count={5} /></div>;
  if (error && !data) return (
    <div className="panel p-4 text-center">
      <p className="text-xs mb-2" style={{ color: "var(--critical)" }}>Erreur de chargement</p>
      <p className="text-[10px] mb-3" style={{ color: "var(--text-secondary)" }}>{error}</p>
      <button onClick={() => { setLoading(true); load(); }} className="btn-primary text-xs">Réessayer</button>
    </div>
  );
  if (!data) return null;

  const { tool_summary, related_assets } = data;
  const total = tool_summary.length;
  const done = tool_summary.filter((t) => t.latest_status === "completed" || t.latest_status === "completed_no_data" || t.latest_status === "failed").length;
  const running = tool_summary.filter((t) => t.latest_status === "running" || t.latest_status === "pending").length;
  const failed = tool_summary.filter((t) => t.latest_status === "failed").length;
  const scanning = running > 0;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;

  return (
    <div className="space-y-4">
      {/* ── Hero ───────────────────────────────────────────────── */}
      <div className="panel overflow-hidden" style={{ position: "relative" }}>
        {scanning && <div className="scan-sweep" style={{ position: "absolute", inset: 0, zIndex: 0 }} />}
        <div style={{ position: "relative", zIndex: 1, padding: "20px 24px" }}>
          <button onClick={onBackToDashboard} className="text-xs font-semibold mb-2 flex items-center gap-1 hover:underline" style={{ color: "var(--text-secondary)" }}>← Tableau de bord</button>
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div>
              <p className="eyebrow mb-1">Cible analysée</p>
              <div className="flex items-center gap-3 flex-wrap">
                <p className="mono text-xl font-bold" style={{ color: "var(--text-primary)" }}>{asset.value}</p>
                <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full"
                  style={{ color: scanning ? "var(--high)" : "var(--success)", background: scanning ? "var(--high-dim)" : "var(--success-dim)" }}>
                  {scanning ? "● En cours" : "● Terminé"}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── KPI ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-5 gap-2">
        {[
          { label: "Catégories", value: Object.keys(grouped).length, color: "var(--brand-accent)" },
          { label: "Outils", value: total, color: "var(--text-primary)" },
          { label: "Terminés", value: done, color: "var(--success)" },
          { label: "En cours", value: running, color: "var(--high)" },
          { label: "Échecs", value: failed, color: failed > 0 ? "var(--critical)" : "var(--text-primary)" },
        ].map((k) => (
          <div key={k.label} className="panel card-pad text-center">
            <p className="text-xl font-extrabold tabular-nums" style={{ color: k.color, fontFamily: "var(--font-manrope)" }}>{k.value}</p>
            <p className="text-[10px] font-semibold uppercase tracking-[0.06em] mt-1" style={{ color: "var(--text-secondary)" }}>{k.label}</p>
          </div>
        ))}
      </div>

      {/* Progress bar */}
      <div className="progress-track"><div className="progress-fill" style={{ width: `${pct}%`, transition: "width 0.5s ease" }} /></div>

      {/* ── Topology with expand ────────────────────────────────── */}
      <div className="relative">
        <button onClick={() => setTopoExpanded(!topoExpanded)}
          className="absolute top-2 right-2 z-10 text-[9px] font-semibold uppercase px-2 py-1 rounded"
          style={{ color: "var(--brand-accent)", background: "var(--brand-dim)", border: "1px solid var(--brand-accent)" }}>
          {topoExpanded ? "Réduire" : "Agrandir"}
        </button>
        <TopologyMap asset={asset} toolSummary={tool_summary} relatedAssets={related_assets} onSelectJob={onSelectJob} onJumpToAsset={onJumpToAsset} onCancelJob={cancelJob} onSelectCategory={scrollToCategory} />
      </div>

      {/* ── Fullscreen topology overlay ─────────────────────────── */}
      {topoExpanded && (
        <div style={{ position: "fixed", inset: 0, zIndex: 50, background: "var(--canvas)", display: "flex", flexDirection: "column" }}>
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-3 shrink-0" style={{ borderBottom: "1px solid var(--border)", background: "var(--panel)" }}>
            <div className="flex items-center gap-4">
              <button onClick={() => setTopoExpanded(false)} className="text-xs font-semibold flex items-center gap-1 hover:underline"
                style={{ color: "var(--brand-accent)" }}>
                ← Fermer
              </button>
              <span className="text-xs font-bold" style={{ color: "var(--text-primary)" }}>Topologie — {asset.value}</span>
            </div>
            <span className="text-[10px]" style={{ color: "var(--text-secondary)" }}>
              {related_assets.length} actif{related_assets.length!==1?"s":""} lié{related_assets.length!==1?"s":""} · {Object.keys(grouped).length} catégories
            </span>
          </div>
          {/* Main content: topology + asset chain */}
          <div className="flex-1 overflow-auto p-4 space-y-4">
            <div className="panel p-4" style={{ background: "var(--panel-dim)" }}>
              <TopologyMap asset={asset} toolSummary={tool_summary} relatedAssets={related_assets} onSelectJob={onSelectJob} onJumpToAsset={onJumpToAsset} onCancelJob={cancelJob} onSelectCategory={scrollToCategory} />
            </div>
            {/* Asset hierarchy chain */}
            <div className="panel p-4">
              <p className="eyebrow mb-3">Chaîne de découverte</p>
              <div className="space-y-2">
                {/* Root */}
                <div className="flex items-center gap-2 text-sm">
                  <span style={{ color: "var(--brand-accent)", fontWeight: 700 }}>🌐 {asset.value}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ color: "var(--text-secondary)", background: "var(--panel-dim)" }}>{asset.asset_type}</span>
                </div>
                {/* Related assets by type */}
                {(() => {
                  const children = related_assets.filter(ra => ra.relation === "child" || ra.relation === "both");
                  if (children.length === 0) return <p className="text-[11px] ml-6" style={{ color: "var(--text-secondary)" }}>Aucun actif découvert. Lancez un scan.</p>;
                  const byType: Record<string, typeof children> = {};
                  for (const c of children) {
                    const t = c.asset.asset_type;
                    (byType[t] ??= []).push(c);
                  }
                  return Object.entries(byType).map(([tpe, items]) => (
                    <div key={tpe} className="ml-6">
                      <p className="text-[10px] font-semibold uppercase mb-1" style={{ color: "var(--text-secondary)" }}>
                        {tpe}s ({items.length})
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {items.map(item => (
                          <button key={item.asset.id} onClick={() => { setTopoExpanded(false); onJumpToAsset(item.asset.id); }}
                            className="text-xs px-2 py-1 rounded flex items-center gap-1 hover:opacity-80"
                            style={{ color: "var(--brand-accent)", background: "var(--brand-dim)", border: "1px solid var(--brand-accent)" }}>
                            {item.asset.asset_type === "ip" ? "🖥" : item.asset.asset_type === "subdomain" ? "🔗" : item.asset.asset_type === "domain" ? "🌐" : item.asset.asset_type === "email" ? "📧" : "•"} {item.asset.value}
                          </button>
                        ))}
                      </div>
                    </div>
                  ));
                })()}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Modules by category ────────────────────────────────── */}
      {Object.entries(grouped).map(([cat, tools]) => {
        const info = categoryInfo(cat);
        const catDone = tools.filter((t) => t.latest_status === "completed" || t.latest_status === "completed_no_data" || t.latest_status === "failed").length;
        const catRunning = tools.filter((t) => t.latest_status === "running" || t.latest_status === "pending").length;
        return (
          <div key={cat} className="panel overflow-hidden" ref={(el) => { categoryRefs.current[cat] = el; }}>
            <div className="px-4 py-3 flex items-center justify-between" style={{ background: info.bgColor, borderBottom: "1px solid var(--border)" }}>
              <div className="flex items-center gap-2">
                <span style={{ fontSize: "16px" }}>{info.emoji}</span>
                <span className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>{info.label}</span>
              </div>
              <div className="flex items-center gap-2">
                {catRunning > 0 && <span className="status-dot status-dot--live" />}
                <span className="text-[10px] font-medium" style={{ color: "var(--text-secondary)" }}>{catDone}/{tools.length}</span>
                {catRunning > 0 && tools.some((t) => t.latest_status === "running" && t.latest_job) && (
                  <button onClick={() => { tools.forEach((t) => { if (t.latest_job && (t.latest_status === "running" || t.latest_status === "pending")) cancelJob(t.latest_job.id); }); }}
                    className="text-[9px] font-semibold uppercase px-2 py-0.5 rounded"
                    style={{ color: "var(--critical)", background: "var(--critical-dim)", border: "1px solid var(--critical)" }}>
                    Annuler
                  </button>
                )}
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
                      <span className="text-[10px] tabular-nums font-bold px-1.5 py-0.5 rounded" style={{ color: "var(--success)", background: "var(--success-dim)" }}>{ts.finding_count}</span>
                    )}
                    {!hasRun && ts.applicable && (
                      <button onClick={() => runTool(ts.tool)} className="text-[10px] font-semibold uppercase hover:underline" style={{ color: "var(--brand-accent)" }}>Lancer</button>
                    )}
                    {(isDone || isFailed || !ts.applicable) && !isActive && (
                      <button onClick={() => runTool(ts.tool)} className="text-[10px] font-semibold uppercase hover:underline" style={{ color: "var(--text-secondary)" }}>Relancer</button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {/* ── Reputation (root domains only) ─────────────────────── */}
      {asset.asset_type === "domain" && (
        <DomainReputation apiBase={apiBase} asset={asset} refreshKey={refreshKey} onJumpToAsset={onJumpToAsset} />
      )}
    </div>
  );
}
