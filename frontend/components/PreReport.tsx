"use client";

import { Asset, DashboardToolSummary, Finding } from "../types/scan";
import { severityLabel, findingTypeLabel } from "../lib/labels";

interface Props {
  asset: Asset;
  findings: Finding[];
  toolSummary: DashboardToolSummary[];
}

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_COLOR: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--text-secondary)",
};

export default function PreReport({ asset, findings, toolSummary }: Props) {
  const completedTools = toolSummary.filter((t) => t.latest_status === "completed").length;
  const totalTools = toolSummary.length;

  // Top findings by severity
  const topFindings = [...findings]
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    .slice(0, 6);

  return (
    <div className="panel overflow-hidden">
      {/* Header */}
      <div
        className="px-6 py-4 flex items-center justify-between"
        style={{ borderBottom: "1px solid var(--border)", background: "var(--surface-deep)" }}
      >
        <div>
          <p
            className="text-sm font-bold"
            style={{ color: "var(--text-on-dark)", fontFamily: "var(--font-manrope)" }}
          >
            Résumé Exécutif
          </p>
          <p
            className="text-[10px] uppercase tracking-[0.06em]"
            style={{ color: "var(--text-on-dark-soft)" }}
          >
            External Attack Surface Management
          </p>
        </div>
      </div>

      <div className="p-6 space-y-5">
        {/* ── Target row ─────────────────────────────────────── */}
        <div className="flex items-start gap-6 flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <p className="eyebrow mb-2">Domaine analysé</p>
            <p className="mono text-lg font-bold" style={{ color: "var(--text-primary)" }}>
              {asset.value}
            </p>
            <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
              {asset.asset_type} · {completedTools}/{totalTools} outils
            </p>
          </div>
        </div>

        {/* ── Top findings ──────────────────────────────────── */}
        {topFindings.length > 0 && (
          <div>
            <p className="eyebrow mb-3">Résultats clés</p>
            <div className="space-y-2">
              {topFindings.map((f) => (
                <div
                  key={f.id}
                  className="flex items-start gap-3 text-sm p-3 rounded-md"
                  style={{ background: "var(--panel-dim)" }}
                >
                  <span
                    className="text-xs font-bold uppercase shrink-0 mt-px px-1.5 py-0.5 rounded"
                    style={{
                      color: SEV_COLOR[f.severity],
                      background: `${SEV_COLOR[f.severity]}1a`,
                    }}
                  >
                    {severityLabel(f.severity)}
                  </span>
                  <div>
                    <p className="font-semibold" style={{ color: "var(--text-primary)" }}>
                      {f.title}
                    </p>
                    <p className="text-[10px] mt-0.5" style={{ color: "var(--text-secondary)" }}>
                      {findingTypeLabel(f.finding_type)}
                    </p>
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
