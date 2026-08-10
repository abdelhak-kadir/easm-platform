"use client";

import { useState, useMemo } from "react";
import { ScanJob } from "../types/scan";
import { toolLabel } from "../lib/labels";
import { timeAgo, formatElapsed } from "../lib/time";
import StatusBadge from "./StatusBadge";

/* ── FleetJob shape ───────────────────────────────────────────────── */

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
  service: "Service",
  technology: "Technologie",
};

/* ── Sort ────────────────────────────────────────────────────────── */

type SortKey = "id" | "asset" | "tool" | "status" | "date";
type SortDir = "asc" | "desc";

/* ── Props ───────────────────────────────────────────────────────── */

interface Props {
  jobs: FleetJob[];
  onSelectAsset: (id: number) => void;
  onSelectJob: (job: ScanJob) => void;
  onCancel: (jobId: number) => void;
}

/* ── Component ───────────────────────────────────────────────────── */

export default function ScanDataTable({
  jobs,
  onSelectAsset,
  onSelectJob,
  onCancel,
}: Props) {
  const [sortBy, setSortBy] = useState<SortKey>("date");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  function toggleSort(key: SortKey) {
    if (sortBy === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(key);
      setSortDir("desc");
    }
  }

  function sortIcon(key: SortKey): string {
    if (sortBy !== key) return "↕";
    return sortDir === "asc" ? "↑" : "↓";
  }

  const sortedJobs = useMemo(() => {
    const arr = [...jobs];
    arr.sort((a, b) => {
      let cmp = 0;
      switch (sortBy) {
        case "id":
          cmp = a.id - b.id;
          break;
        case "asset":
          cmp = (a.asset_value || "").localeCompare(b.asset_value || "");
          break;
        case "tool":
          cmp = (a.tool || "").localeCompare(b.tool || "");
          break;
        case "status":
          cmp = (a.status || "").localeCompare(b.status || "");
          break;
        case "date":
        default: {
          const at = a.completed_at || a.created_at || "";
          const bt = b.completed_at || b.created_at || "";
          cmp = at.localeCompare(bt);
          break;
        }
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return arr;
  }, [jobs, sortBy, sortDir]);

  const hasActiveJobs = jobs.some(
    (j) => j.status === "running" || j.status === "pending"
  );

  if (jobs.length === 0) {
    return (
      <div className="panel">
        <div
          className="px-5 py-3 flex items-center justify-between"
          style={{ borderBottom: "1px solid var(--border)" }}
        >
          <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
            Activité récente
          </p>
        </div>
        <p
          className="px-5 py-8 text-sm text-center"
          style={{ color: "var(--text-secondary)" }}
        >
          Aucune activité récente.
        </p>
      </div>
    );
  }

  return (
    <div className="panel overflow-hidden">
      <div
        className="px-5 py-3 flex items-center justify-between"
        style={{ borderBottom: "1px solid var(--border)" }}
      >
        <div className="flex items-center gap-2">
          <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
            Activité récente
          </p>
          {hasActiveJobs && <span className="status-dot status-dot--live" />}
        </div>
        <span className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
          {jobs.length} scan{jobs.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div style={{ overflowX: "auto" }}>
        <table
          className="data-table"
          style={{ width: "100%", borderCollapse: "collapse" }}
        >
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border)" }}>
              <Th label="ID" sortKey="id" sortBy={sortBy} sortIcon={sortIcon} onClick={toggleSort} />
              <Th label="Actif" sortKey="asset" sortBy={sortBy} sortIcon={sortIcon} onClick={toggleSort} />
              <Th label="Outil" sortKey="tool" sortBy={sortBy} sortIcon={sortIcon} onClick={toggleSort} />
              <Th label="Statut" sortKey="status" sortBy={sortBy} sortIcon={sortIcon} onClick={toggleSort} />
              <th
                className="text-[10px] font-semibold uppercase tracking-[0.05em] px-3 py-2 text-left"
                style={{ color: "var(--text-secondary)" }}
              >
                Résultats
              </th>
              <Th label="Date" sortKey="date" sortBy={sortBy} sortIcon={sortIcon} onClick={toggleSort} />
              <th
                className="text-[10px] font-semibold uppercase tracking-[0.05em] px-3 py-2 text-right"
                style={{ color: "var(--text-secondary)" }}
              >
                Actions
              </th>
            </tr>
          </thead>

          <tbody>
            {sortedJobs.map((j) => {
              const isActive = j.status === "running" || j.status === "pending";
              const isCompleted = j.status === "completed";
              const isFailed = j.status === "failed";
              const accentColor = isActive
                ? "var(--high)"
                : isFailed
                  ? "var(--critical)"
                  : isCompleted
                    ? "var(--success)"
                    : "var(--border)";

              const dateStr = j.completed_at || j.created_at;
              const displayDate = dateStr ? timeAgo(dateStr) : "—";
              const timeOfDay = dateStr
                ? new Date(dateStr).toLocaleTimeString("fr-FR", {
                    hour: "2-digit",
                    minute: "2-digit",
                  })
                : "";

              return (
                <tr
                  key={j.id}
                  className="data-table-row"
                  style={{
                    borderBottom: "1px solid var(--border)",
                    borderLeft: `3px solid ${accentColor}`,
                    transition: "background 0.15s ease",
                  }}
                >
                  {/* ID */}
                  <td
                    className="px-3 py-2.5 text-xs mono tabular-nums"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    #{j.id}
                  </td>

                  {/* Asset */}
                  <td className="px-3 py-2.5">
                    <button
                      onClick={() => onSelectAsset(j.asset_id)}
                      className="text-xs font-semibold hover:underline text-left"
                      style={{ color: "var(--text-primary)" }}
                    >
                      {j.asset_value}
                    </button>
                    {j.asset_type && (
                      <span
                        className="text-[10px] ml-1.5"
                        style={{ color: "var(--text-secondary)" }}
                      >
                        {ASSET_TYPE_LABEL[j.asset_type] || j.asset_type}
                      </span>
                    )}
                  </td>

                  {/* Tool */}
                  <td
                    className="px-3 py-2.5 text-xs"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    {toolLabel(j.tool).split(" (")[0]}
                  </td>

                  {/* Status */}
                  <td className="px-3 py-2.5">
                    <StatusBadge
                      status={j.status}
                      pulsing={isActive}
                    />
                  </td>

                  {/* Results summary */}
                  <td
                    className="px-3 py-2.5 text-xs"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    {isActive ? (
                      <span style={{ color: "var(--high)" }}>
                        {j.started_at ? `Depuis ${formatElapsed(j.started_at)}` : "En attente…"}
                      </span>
                    ) : isFailed ? (
                      <span style={{ color: "var(--critical)" }}>
                        {j.error_message
                          ? j.error_message.length > 40
                            ? j.error_message.slice(0, 40) + "…"
                            : j.error_message
                          : "Erreur"}
                      </span>
                    ) : isCompleted ? (
                      <span>—</span>
                    ) : (
                      <span>—</span>
                    )}
                  </td>

                  {/* Date */}
                  <td
                    className="px-3 py-2.5 text-xs tabular-nums whitespace-nowrap"
                    style={{ color: "var(--text-secondary)" }}
                    title={dateStr || undefined}
                  >
                    {displayDate}
                    {timeOfDay && (
                      <span className="ml-1" style={{ opacity: 0.6 }}>
                        {timeOfDay}
                      </span>
                    )}
                  </td>

                  {/* Actions */}
                  <td className="px-3 py-2.5 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      {isCompleted && (
                        <button
                          onClick={() => onSelectJob(j)}
                          className="text-[10px] font-semibold uppercase tracking-[0.04em] px-1.5 py-0.5 rounded transition-colors hover:underline"
                          style={{ color: "var(--brand-accent)" }}
                        >
                          👁 Voir
                        </button>
                      )}
                      {isActive && (
                        <button
                          onClick={() => onCancel(j.id)}
                          className="text-[10px] font-semibold uppercase tracking-[0.04em] px-1.5 py-0.5 rounded-full transition-colors"
                          style={{
                            color: "var(--critical)",
                            background: "var(--critical-dim)",
                            border: "1px solid var(--critical)",
                          }}
                        >
                          Annuler
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ── Sortable table header ────────────────────────────────────────── */

function Th({
  label,
  sortKey,
  sortBy,
  sortIcon,
  onClick,
}: {
  label: string;
  sortKey: SortKey;
  sortBy: SortKey;
  sortIcon: (key: SortKey) => string;
  onClick: (key: SortKey) => void;
}) {
  const isActive = sortBy === sortKey;
  return (
    <th
      className="text-[10px] font-semibold uppercase tracking-[0.05em] px-3 py-2 text-left cursor-pointer select-none transition-colors hover:text-[var(--text-primary)]"
      style={{ color: isActive ? "var(--text-primary)" : "var(--text-secondary)" }}
      onClick={() => onClick(sortKey)}
    >
      {label}{" "}
      <span style={{ fontSize: "9px", opacity: 0.5 }}>{sortIcon(sortKey)}</span>
    </th>
  );
}
