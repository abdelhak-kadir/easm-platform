import { Asset } from "../types/scan";
import { FleetJob } from "../lib/useFleetScans";
import { timeAgo } from "../lib/time";

const STATUS_STYLE: Record<string, { color: string; bg: string }> = {
  completed: { color: "var(--success)", bg: "var(--success-dim)" },
  failed: { color: "var(--danger)", bg: "var(--danger-dim)" },
  running: { color: "var(--warning)", bg: "var(--warning-dim)" },
  pending: { color: "var(--muted)", bg: "var(--panel-alt)" },
};

interface OverviewStripProps {
  assets: Asset[];
  jobs: FleetJob[];
  activeCount: number;
  onSelectAsset: (assetId: number) => void;
}

export default function OverviewStrip({ assets, jobs, activeCount, onSelectAsset }: OverviewStripProps) {
  const completedCount = jobs.filter((j) => j.status === "completed").length;
  const lastScan = jobs.find((j) => j.completed_at || j.created_at);

  const kpis = [
    { label: "Targets tracked", value: assets.length },
    { label: "Scans in progress", value: activeCount, tone: activeCount > 0 ? "var(--warning)" : undefined },
    { label: "Scans completed", value: completedCount },
    {
      label: "Last activity",
      value: lastScan ? timeAgo(lastScan.completed_at || lastScan.created_at || "") : "—",
      isText: true,
    },
  ];

  return (
    <section className="mb-8">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {kpis.map((k) => (
          <div key={k.label} className="panel card-pad">
            <p className="eyebrow mb-2">{k.label}</p>
            <p
              className={k.isText ? "text-lg font-semibold" : "text-3xl font-bold tabular-nums"}
              style={{ color: k.tone || "var(--text)" }}
            >
              {k.value}
            </p>
          </div>
        ))}
      </div>

      <div className="panel overflow-hidden">
        <div className="px-5 py-4 flex items-center justify-between" style={{ borderBottom: "1px solid var(--hairline)" }}>
          <h2 className="text-sm font-bold">Recent scans</h2>
          <span className="text-xs" style={{ color: "var(--muted)" }}>
            across all targets
          </span>
        </div>

        {jobs.length === 0 ? (
          <p className="px-5 py-8 text-sm text-center" style={{ color: "var(--muted)" }}>
            No scans yet — add a target and run your first scan to see activity here.
          </p>
        ) : (
          <div className="divide-y" style={{ borderColor: "var(--hairline)" }}>
            {jobs.slice(0, 6).map((j) => {
              const style = STATUS_STYLE[j.status] || STATUS_STYLE.pending;
              return (
                <button
                  key={j.id}
                  onClick={() => onSelectAsset(j.asset_id)}
                  className="w-full text-left px-5 py-3 flex items-center justify-between gap-3 transition-colors"
                  style={{ background: "transparent" }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--panel-alt)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="mono text-sm font-medium truncate">{j.asset_value}</span>
                    <span className="text-xs shrink-0" style={{ color: "var(--muted)" }}>
                      {j.tool}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-xs" style={{ color: "var(--faint)" }}>
                      {timeAgo(j.completed_at || j.created_at || "")}
                    </span>
                    <span
                      className="text-[11px] font-semibold px-2 py-1 rounded-full"
                      style={{ color: style.color, background: style.bg }}
                    >
                      {j.status.toUpperCase()}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}
