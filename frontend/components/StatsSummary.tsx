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
    {
      label: "À corriger en priorité",
      value: criticalOrHigh,
      urgent: criticalOrHigh > 0,
    },
    { label: "Ports ouverts", value: openPorts, urgent: false },
    { label: "Vulnérabilités", value: vulns, urgent: vulns > 0 },
    { label: "Total des résultats", value: findings.length, urgent: false },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      {cols.map((c) => (
        <div key={c.label} className="panel card-pad">
          <p
            className="text-3xl font-extrabold tabular-nums tracking-tight"
            style={{
              color: c.urgent ? "var(--critical)" : "var(--text-primary)",
              fontFamily: "var(--font-manrope)",
            }}
          >
            {c.value}
          </p>
          <p className="text-[11px] font-semibold uppercase tracking-[0.06em] mt-1.5" style={{ color: "var(--text-secondary)" }}>
            {c.label}
          </p>
        </div>
      ))}
    </div>
  );
}
