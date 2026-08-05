import { Finding, Severity } from "../types/scan";
import { SEVERITY_HEX } from "./SeverityBadge";
import { severityLabel } from "../lib/labels";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

interface SeverityChartProps {
  findings: Finding[];
}

export default function SeverityChart({ findings }: SeverityChartProps) {
  const counts: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  findings.forEach((f) => {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  });
  const max = Math.max(...Object.values(counts), 1);

  return (
    <div className="panel card-pad mb-6">
      <h3 className="text-sm font-bold mb-4">Résultats par gravité</h3>
      <div className="space-y-2.5">
        {ORDER.map((sev) => {
          const count = counts[sev];
          const color = SEVERITY_HEX[sev];
          return (
            <div key={sev} className="flex items-center gap-3">
              <span className="w-16 text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                {severityLabel(sev)}
              </span>
              <div className="flex-1 rounded-full h-2 overflow-hidden" style={{ background: "var(--panel-dim)" }}>
                <div
                  className="h-2 rounded-full transition-all"
                  style={{
                    width: `${(count / max) * 100}%`,
                    minWidth: count > 0 ? "8px" : 0,
                    background: color,
                  }}
                />
              </div>
              <span className="w-6 text-xs text-right tabular-nums" style={{ color: "var(--text-secondary)" }}>
                {count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
