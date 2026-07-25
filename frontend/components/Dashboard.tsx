import { useState, useEffect, useCallback } from "react";
import { DashboardScan, ScanStats } from "../types/scan";
import { timeAgo } from "../lib/time";

const STATUS_COLOR: Record<string, string> = {
  completed: "var(--signal)",
  failed: "#E0525C",
  running: "#D9BB4C",
  pending: "var(--muted)",
};

const ACTIVE_STATUSES = new Set(["pending", "running"]);

export default function Dashboard({
  apiBase,
  onOpenScan,
  refreshKey,
}: {
  apiBase: string;
  onOpenScan: (scan: DashboardScan) => void;
  refreshKey: number;
}) {
  const [scans, setScans] = useState<DashboardScan[]>([]);
  const [stats, setStats] = useState<ScanStats | null>(null);

  const load = useCallback(() => {
    fetch(`${apiBase}/scans?limit=25`)
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => setScans(Array.isArray(data) ? data : []))
      .catch(() => setScans([]));
    fetch(`${apiBase}/scans/stats`)
      .then((r) => (r.ok ? r.json() : null))
      .then(setStats)
      .catch(() => setStats(null));
  }, [apiBase]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const hasActive = scans.some((s) => ACTIVE_STATUSES.has(s.status));

  // Only poll while something is actually in flight -- otherwise this
  // would hit the API forever even when the dashboard is just sitting
  // idle on screen.
  useEffect(() => {
    if (!hasActive) return;
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, [hasActive, load]);

  const running = stats?.by_status?.running ?? 0;
  const pending = stats?.by_status?.pending ?? 0;
  const failed = stats?.by_status?.failed ?? 0;
  const completed = stats?.by_status?.completed ?? 0;

  const cols: { label: string; value: number | string; tone?: string }[] = [
    { label: "TARGETS", value: stats?.total_assets ?? "—" },
    { label: "RUNNING", value: running, tone: running > 0 ? "#D9BB4C" : "var(--text)" },
    { label: "PENDING", value: pending },
    { label: "FAILED", value: failed, tone: failed > 0 ? "#E0525C" : "var(--text)" },
    { label: "COMPLETED", value: completed, tone: "var(--signal)" },
  ];

  return (
    <div className="mb-8">
      <div className="eyebrow mb-1.5">DASHBOARD</div>

      <div className="panel flex mb-4 divide-x" style={{ borderColor: "var(--hairline)" }}>
        {cols.map((c) => (
          <div key={c.label} className="flex-1 px-4 py-3" style={{ borderColor: "var(--hairline)" }}>
            <div className="mono text-2xl tabular-nums" style={{ color: c.tone || "var(--text)" }}>
              {c.value}
            </div>
            <div className="eyebrow mt-1">{c.label}</div>
          </div>
        ))}
      </div>

      <div className="eyebrow mb-1.5">RECENT SCANS</div>
      {scans.length === 0 ? (
        <p
          className="mono text-xs px-3 py-4"
          style={{ color: "var(--muted)", border: "1px dashed var(--hairline)" }}
        >
          // no scans yet — add a target below and run one
        </p>
      ) : (
        <div className="panel divide-y" style={{ borderColor: "var(--hairline)" }}>
          {scans.map((s) => (
            <button
              key={s.id}
              onClick={() => onOpenScan(s)}
              className="mono w-full text-left text-sm px-3 py-2 flex justify-between items-center gap-3 transition-colors"
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--panel-alt)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <span className="flex items-center gap-2 min-w-0">
                <span className="truncate">{s.asset_value}</span>
                <span style={{ color: "var(--muted)" }}>
                  · {s.tool} #{s.id}
                </span>
                {s.completed_at && (
                  <span className="text-xs shrink-0" style={{ color: "var(--muted)" }}>
                    {timeAgo(s.completed_at)}
                  </span>
                )}
              </span>
              <span
                className="text-xs tracking-wider shrink-0"
                style={{ color: STATUS_COLOR[s.status] || "var(--muted)" }}
              >
                {s.status.toUpperCase()}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
