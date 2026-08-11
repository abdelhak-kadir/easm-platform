"use client";

import { useState } from "react";
import { DashboardToolSummary, ScanJob } from "../types/scan";
import { toolLabel } from "../lib/labels";
import { categoryInfo } from "../lib/categories";
import StatusBadge from "./StatusBadge";

interface Props {
  category: string;
  tools: DashboardToolSummary[];
  onSelectJob: (job: ScanJob) => void;
  onRunTool: (tool: string) => void;
}

export default function ToolCategoryGroup({ category, tools, onSelectJob, onRunTool }: Props) {
  const [expanded, setExpanded] = useState(true);
  const info = categoryInfo(category);
  const doneCount = tools.filter((t) => t.latest_status === "completed").length;
  const runningCount = tools.filter((t) => t.latest_status === "running" || t.latest_status === "pending").length;
  const failedCount = tools.filter((t) => t.latest_status === "failed").length;

  return (
    <div className="panel mb-4 overflow-hidden">
      {/* Category header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left px-4 py-3 flex items-center justify-between gap-2 transition-colors hover:opacity-80"
        style={{ background: info.bgColor, borderBottom: expanded ? "1px solid var(--border)" : "none" }}
      >
        <div className="flex items-center gap-3">
          <span style={{ fontSize: "18px" }}>{info.emoji}</span>
          <div>
            <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
              {info.label}
            </p>
            <p className="text-[10px]" style={{ color: "var(--text-secondary)" }}>
              {tools.length} outil{tools.length !== 1 ? "s" : ""}
              {doneCount > 0 && ` · ${doneCount} terminé${doneCount !== 1 ? "s" : ""}`}
              {runningCount > 0 && ` · ${runningCount} actif${runningCount !== 1 ? "s" : ""}`}
              {failedCount > 0 && ` · ${failedCount} échec${failedCount !== 1 ? "s" : ""}`}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {runningCount > 0 && <span className="status-dot status-dot--live" />}
          <span style={{ fontSize: "10px", color: "var(--text-secondary)", transform: expanded ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.2s" }}>▼</span>
        </div>
      </button>

      {/* Tool cards */}
      {expanded && (
        <div className="divide-y" style={{ borderColor: "var(--border)" }}>
          {tools.map((ts) => {
            const isActive = ts.latest_status === "pending" || ts.latest_status === "running";
            const isDone = ts.latest_status === "completed";
            const isFailed = ts.latest_status === "failed";
            const hasRun = ts.latest_job !== null;

            const accentColor = isActive ? "var(--high)" : isFailed ? "var(--critical)" : isDone && ts.finding_count > 0 ? "var(--success)" : "var(--border)";

            return (
              <div key={ts.tool} className="flex items-center gap-3 px-4 py-2.5 text-sm" style={{ borderLeft: `3px solid ${accentColor}` }}>
                <button
                  onClick={() => ts.latest_job && onSelectJob(ts.latest_job)}
                  className="flex-1 text-left truncate font-medium transition-colors hover:underline"
                  style={{ color: "var(--text-primary)", cursor: ts.latest_job ? "pointer" : "default" }}
                >
                  {toolLabel(ts.tool).split(" (")[0]}
                </button>
                {ts.latest_status && <StatusBadge status={ts.latest_status} pulsing={isActive} />}
                {isDone && ts.finding_count > 0 && (
                  <span className="text-[10px] tabular-nums font-semibold" style={{ color: "var(--success)" }}>
                    {ts.finding_count}
                  </span>
                )}
                {!hasRun && ts.applicable && (
                  <button onClick={() => onRunTool(ts.tool)} className="text-[10px] font-semibold uppercase" style={{ color: "var(--brand-accent)" }}>
                    Lancer
                  </button>
                )}
                {(isDone || isFailed || !ts.applicable) && !isActive && (
                  <button onClick={() => onRunTool(ts.tool)} className="text-[10px] font-semibold uppercase" style={{ color: "var(--text-secondary)" }}>
                    Relancer
                  </button>
                )}
                {isActive && (
                  <span className="text-[10px] font-semibold" style={{ color: "var(--high)" }}>En cours</span>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
