import { Finding, Severity } from "../types/scan";

interface StatsSummaryProps {
  findings: Finding[];
}

export default function StatsSummary({ findings }: StatsSummaryProps) {
  const bySeverity = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<Severity, number>);

  const openPorts = findings.filter((f) => f.finding_type === "open_port").length;
  const vulns = findings.filter((f) => f.finding_type === "vulnerability").length;
  const criticalOrHigh = (bySeverity.critical || 0) + (bySeverity.high || 0);

  const cols = [
    { label: "À corriger en priorité", value: criticalOrHigh, tone: criticalOrHigh > 0 ? "var(--danger)" : "var(--text)" },
    { label: "Ports ouverts", value: openPorts, tone: "var(--text)" },
    { label: "Vulnérabilités", value: vulns, tone: vulns > 0 ? "var(--warning)" : "var(--text)" },
    { label: "Résultats au total", value: findings.length, tone: "var(--text)" },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      {cols.map((c) => (
        <div key={c.label} className="panel card-pad">
          <p className="text-3xl font-bold tabular-nums" style={{ color: c.tone }}>
            {c.value}
          </p>
          <p className="eyebrow mt-1.5">{c.label}</p>
        </div>
      ))}
    </div>
  );
}
