"use client";

import { Asset, DashboardToolSummary, Finding, ScanJob } from "../types/scan";
import { severityLabel, findingTypeLabel } from "../lib/labels";

interface Props {
  asset: Asset;
  risk: { score: number; breakdown: Record<string, number>; finding_count: number; cve_count: number; exposed_ports: number } | null;
  findings: Finding[];
  toolSummary: DashboardToolSummary[];
  scanJobs: ScanJob[];
}

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_COLOR: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--text-secondary)",
};

export default function PreReport({ asset, risk, findings, toolSummary, scanJobs }: Props) {
  const score = risk?.score ?? 0;
  const scorePct = Math.min(100, Math.max(0, score));
  const completedTools = toolSummary.filter((t) => t.latest_status === "completed").length;
  const totalTools = toolSummary.length;
  const totalFindings = risk?.finding_count ?? findings.length;
  const cveCount = risk?.cve_count ?? 0;
  const portCount = risk?.exposed_ports ?? 0;

  const tier = score >= 70 ? { label: "Critique", color: "var(--critical)", bg: "var(--critical-dim)" }
    : score >= 40 ? { label: "Modéré", color: "var(--high)", bg: "var(--high-dim)" }
    : { label: "Faible", color: "var(--success)", bg: "var(--success-dim)" };

  // Top findings by severity
  const topFindings = [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)).slice(0, 6);

  // Domain info
  const whoisJob = scanJobs.find((j) => j.tool === "whois" && j.status === "completed");
  const sslJob = scanJobs.find((j) => j.tool === "ssl_checker" && j.status === "completed");
  const emailJob = scanJobs.find((j) => j.tool === "email_security" && j.status === "completed");

  return (
    <div className="panel overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: "1px solid var(--border)", background: "var(--surface-deep)" }}>
        <div>
          <p className="text-sm font-bold" style={{ color: "var(--text-on-dark)", fontFamily: "var(--font-manrope)" }}>Résumé Exécutif</p>
          <p className="text-[10px] uppercase tracking-[0.06em]" style={{ color: "var(--text-on-dark-soft)" }}>External Attack Surface Management</p>
        </div>
      </div>

      <div className="p-6 space-y-5">
        {/* ── Hero row: domain + gauge + risk ───────────────────── */}
        <div className="flex items-start gap-6 flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <p className="eyebrow mb-2">Domaine analysé</p>
            <p className="mono text-lg font-bold" style={{ color: "var(--text-primary)" }}>{asset.value}</p>
            <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>{asset.asset_type} · {completedTools}/{totalTools} outils</p>
          </div>

          {/* Radar gauge */}
          <div className="flex flex-col items-center">
            <div style={{ position: "relative", width: 100, height: 100 }}>
              <svg width="100" height="100" viewBox="0 0 100 100" style={{ transform: "rotate(-90deg)" }}>
                <circle cx="50" cy="50" r="40" fill="none" stroke="var(--border)" strokeWidth="6" />
                <circle cx="50" cy="50" r="40" fill="none" stroke={tier.color} strokeWidth="6" strokeLinecap="round"
                  strokeDasharray={251.3} strokeDashoffset={251.3 * (1 - scorePct / 100)}
                  style={{ transition: "stroke-dashoffset 0.8s ease" }} />
              </svg>
              <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                <span className="text-xl font-extrabold tabular-nums" style={{ color: tier.color, fontFamily: "var(--font-manrope)" }}>{score}</span>
                <span className="text-[9px] uppercase" style={{ color: "var(--text-secondary)" }}>/100</span>
              </div>
            </div>
            <span className="text-[10px] font-semibold uppercase mt-1" style={{ color: tier.color }}>{tier.label}</span>
          </div>

          {/* Risk breakdown */}
          <div className="flex-1 min-w-[150px]">
            <p className="eyebrow mb-2">Sévérité</p>
            <div className="space-y-1">
              {SEV_ORDER.map((s) => {
                const count = risk?.breakdown?.[s] ?? 0;
                const maxCount = Math.max(...Object.values(risk?.breakdown || {}), 1);
                return (
                  <div key={s} className="flex items-center gap-2 text-[11px]">
                    <span className="w-12 text-right uppercase font-semibold" style={{ color: SEV_COLOR[s] }}>{severityLabel(s)}</span>
                    <div className="flex-1 h-3 rounded-sm overflow-hidden" style={{ background: "var(--panel-dim)" }}>
                      <div className="h-full rounded-sm" style={{ width: `${(count / maxCount) * 100}%`, background: SEV_COLOR[s], transition: "width 0.5s ease" }} />
                    </div>
                    <span className="w-6 tabular-nums text-right font-bold" style={{ color: SEV_COLOR[s] }}>{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* ── Status row ────────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { title: "Surface", ok: portCount === 0, summary: portCount === 0 ? "Faible exposition" : `${portCount} ports`, detail: `${cveCount} CVE · ${totalFindings} findings` },
            { title: "SSL/TLS", ok: !sslJob?.error_message, summary: sslJob ? "Analysé" : "Non testé", detail: sslJob?.status ?? "—" },
            { title: "Email", ok: !emailJob?.error_message, summary: emailJob ? "Analysé" : "Non testé", detail: emailJob?.status ?? "—" },
          ].map((card) => (
            <div key={card.title} className="panel card-pad">
              <p className="text-[10px] font-semibold uppercase tracking-[0.05em] mb-2" style={{ color: "var(--text-secondary)" }}>{card.title}</p>
              <p className="text-sm font-bold" style={{ color: card.ok ? "var(--success)" : "var(--high)" }}>{card.summary}</p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-secondary)" }}>{card.detail}</p>
            </div>
          ))}
        </div>

        {/* ── Top findings ──────────────────────────────────────── */}
        {topFindings.length > 0 && (
          <div>
            <p className="eyebrow mb-3">Résultats clés</p>
            <div className="space-y-2">
              {topFindings.map((f) => (
                <div key={f.id} className="flex items-start gap-3 text-sm p-3 rounded-md" style={{ background: "var(--panel-dim)" }}>
                  <span className="text-xs font-bold uppercase shrink-0 mt-px px-1.5 py-0.5 rounded" style={{ color: SEV_COLOR[f.severity], background: `${SEV_COLOR[f.severity]}1a` }}>
                    {severityLabel(f.severity)}
                  </span>
                  <div>
                    <p className="font-semibold" style={{ color: "var(--text-primary)" }}>{f.title}</p>
                    <p className="text-[10px] mt-0.5" style={{ color: "var(--text-secondary)" }}>{findingTypeLabel(f.finding_type)}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
