"use client";

/** Shared status badge — single source of truth for job/run status pills. */

type StatusVariant = "completed" | "failed" | "running" | "pending" | "cancelled";

const STATUS_MAP: Record<string, StatusVariant> = {
  completed: "completed",
  failed: "failed",
  running: "running",
  pending: "pending",
  cancelled: "cancelled",
  max_rounds_reached: "completed",
};

const CONFIG: Record<StatusVariant, { color: string; bg: string; label: string }> = {
  completed: { color: "var(--success)", bg: "var(--success-dim)", label: "Terminée" },
  failed: { color: "var(--critical)", bg: "var(--critical-dim)", label: "Échouée" },
  running: { color: "var(--high)", bg: "var(--high-dim)", label: "En cours" },
  pending: { color: "var(--text-secondary)", bg: "var(--panel-dim)", label: "En attente" },
  cancelled: { color: "var(--critical)", bg: "var(--critical-dim)", label: "Annulée" },
};

export function statusVariant(status: string): StatusVariant {
  return STATUS_MAP[status] || "pending";
}

export function statusColor(status: string): string {
  return CONFIG[statusVariant(status)].color;
}

export function statusBg(status: string): string {
  return CONFIG[statusVariant(status)].bg;
}

export function statusLabel(status: string): string {
  return CONFIG[statusVariant(status)].label;
}

interface Props {
  status: string;
  pulsing?: boolean;
  className?: string;
}

export default function StatusBadge({ status, pulsing, className = "" }: Props) {
  const v = statusVariant(status);
  const cfg = CONFIG[v];
  const isRunning = v === "running" || v === "pending";

  return (
    <span
      className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full shrink-0 inline-flex items-center gap-1.5 ${className}`}
      style={{ color: cfg.color, background: cfg.bg, minWidth: 48, textAlign: "center" as any }}
      title={cfg.label}
    >
      {pulsing && isRunning && <span className="status-dot status-dot--live" />}
      {cfg.label}
    </span>
  );
}
