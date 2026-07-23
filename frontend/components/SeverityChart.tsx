import { Finding, Severity } from "../types/scan";

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
    <div className="mb-6 bg-gray-900 rounded p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3">Findings by severity</h3>
      <div className="space-y-2">
        {ORDER.map((sev) => {
          const count = counts[sev];
          return (
            <div key={sev} className="flex items-center gap-3">
              <span className="w-16 text-xs text-gray-400 capitalize">{sev}</span>
              <div className="flex-1 bg-gray-800 rounded h-4 overflow-hidden">
                <div
                  className="h-4 transition-all"
                  style={{ width: `${(count / max) * 100}%`, minWidth: count > 0 ? "8px" : 0 }}
                />
              </div>
              <span className="w-6 text-xs text-gray-400 text-right">{count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
