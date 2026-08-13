"use client";

import { Asset } from "../types/scan";
import { toolLabel } from "../lib/labels";
import { timeAgo, formatElapsed } from "../lib/time";
import StatusBadge from "./StatusBadge";

/* ── Fleet-level derived health ──────────────────────────────────── */

export interface AssetHealth {
  activeJobs: number;
  failedCount: number;
  completedCount: number;
  totalJobs: number;
  lastJobTool?: string;
  lastJobStatus?: string;
  lastCompletedAt?: string;
  lastStartedAt?: string;
  isRunning: boolean;
}

interface FleetJob {
  id: number;
  asset_id: number;
  asset_value: string;
  asset_type?: string;
  tool: string;
  status: string;
  created_at?: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string | null;
}

const ASSET_TYPE_LABEL: Record<string, string> = {
  domain: "Domaine",
  subdomain: "Sous-domaine",
  ip: "IP",
  email: "Email",
  service: "Service",
  technology: "Technologie",
};

const ASSET_EMOJI: Record<string, string> = {
  domain: "",
  subdomain: "",
  ip: "",
  email: "",
  service: "",
  technology: "",
};

/* ── Props ───────────────────────────────────────────────────────── */

interface Props {
  assets: Asset[];
  assetHealth: Map<number, AssetHealth>;
  onSelectAsset: (id: number) => void;
}

/* ── Component ───────────────────────────────────────────────────── */

export default function AssetCardGrid({ assets, assetHealth, onSelectAsset }: Props) {
  if (assets.length === 0) return null;

  return (
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
          return (
            <AssetCard
              key={a.id}
              asset={a}
              health={health}
              onClick={() => onSelectAsset(a.id)}
            />
          );
        })}
      </div>
    </div>
  );
}

/* ── Single card ─────────────────────────────────────────────────── */

function AssetCard({
  asset,
  health,
  onClick,
}: {
  asset: Asset;
  health?: AssetHealth;
  onClick: () => void;
}) {
  const hasActive = (health?.activeJobs ?? 0) > 0;
  const hasFailed = (health?.failedCount ?? 0) > 0;
  const hasCompleted = (health?.completedCount ?? 0) > 0;
  const isRunning = health?.isRunning ?? false;

  // Left border colour
  let borderColor = "var(--border)";
  let statusLabel = "Vierge";
  let statusColor = "var(--text-secondary)";
  let statusBg = "var(--panel-dim)";

  if (isRunning) {
    borderColor = "var(--brand-accent)";
    statusLabel = "Actif";
    statusColor = "var(--brand-accent)";
    statusBg = "var(--brand-dim)";
  } else if (hasFailed && !hasCompleted) {
    borderColor = "var(--critical)";
    statusLabel = "Échec";
    statusColor = "var(--critical)";
    statusBg = "var(--critical-dim)";
  } else if (hasCompleted && !hasFailed) {
    borderColor = "var(--success)";
    statusLabel = "Vérifié";
    statusColor = "var(--success)";
    statusBg = "var(--success-dim)";
  } else if (hasCompleted && hasFailed) {
    borderColor = "var(--high)";
    statusLabel = "Partiel";
    statusColor = "var(--high)";
    statusBg = "var(--high-dim)";
  } else if (asset.status === "done") {
    borderColor = "var(--success)";
    statusLabel = "Analysé";
    statusColor = "var(--success)";
    statusBg = "var(--success-dim)";
  }

  const typeLabel = ASSET_TYPE_LABEL[asset.asset_type] || asset.asset_type;
  const emoji = ASSET_EMOJI[asset.asset_type] || "•";
  const totalJobs = health?.totalJobs ?? 0;
  const completedJobs = health?.completedCount ?? 0;

  return (
    <button
      onClick={onClick}
      className="panel text-left transition-all hover:shadow-[var(--shadow-elevated)] cursor-pointer overflow-hidden"
      style={{ borderLeft: `3px solid ${borderColor}` }}
    >
      {/* Header */}
      <div className="px-4 py-3 flex items-center gap-2">
        <span className="text-base" style={{ lineHeight: 1 }}>
          {emoji}
        </span>
        <span
          className="mono text-sm font-semibold truncate flex-1"
          style={{ color: "var(--text-primary)" }}
        >
          {asset.value}
        </span>
        <span
          className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full shrink-0"
          style={{ color: statusColor, background: statusBg }}
        >
          {statusLabel}
        </span>
      </div>

      {/* Body — stat rows */}
      <div
        className="px-4 py-2 space-y-1.5"
        style={{ borderTop: "1px solid var(--border)", background: "var(--panel-dim)" }}
      >
        <StatRow label="Type" value={typeLabel} />
        <StatRow
          label="Outils exécutés"
          value={totalJobs > 0 ? `${completedJobs}/${totalJobs}` : "—"}
          accent={hasActive ? "var(--brand-accent)" : undefined}
        />
        <StatRow
          label="Dernier scan"
          value={
            health?.lastJobTool
              ? `${toolLabel(health.lastJobTool).split(" (")[0]}`
              : "—"
          }
        />
        {hasActive && health?.lastStartedAt && (
          <StatRow
            label="En cours depuis"
            value={formatElapsed(health.lastStartedAt)}
            accent="var(--high)"
          />
        )}
        {!hasActive && health?.lastCompletedAt && (
          <StatRow
            label="Dernière analyse"
            value={timeAgo(health.lastCompletedAt)}
          />
        )}
        {hasFailed && (
          <StatRow
            label="Échecs"
            value={`${health!.failedCount} erreur${health!.failedCount !== 1 ? "s" : ""}`}
            accent="var(--critical)"
          />
        )}
        {/* Discovery run indicator */}
        {asset.discovery_run_id != null && !isRunning && (
          <StatRow label="Découverte" value="Terminée" accent="var(--success)" />
        )}
      </div>
    </button>
  );
}

/* ── Tiny stat row ───────────────────────────────────────────────── */

function StatRow({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: string;
}) {
  return (
    <div className="flex items-center justify-between text-[11px]">
      <span style={{ color: "var(--text-secondary)" }}>{label}</span>
      <span
        className="font-medium tabular-nums"
        style={{ color: accent || "var(--text-primary)" }}
      >
        {value}
      </span>
    </div>
  );
}
