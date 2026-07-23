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
    { label: "NEEDS ATTENTION", value: criticalOrHigh, tone: criticalOrHigh > 0 ? "#E0525C" : "var(--text)" },
    { label: "OPEN PORTS", value: openPorts, tone: "var(--text)" },
    { label: "VULNERABILITIES", value: vulns, tone: vulns > 0 ? "#E08A4B" : "var(--text)" },
    { label: "TOTAL FINDINGS", value: findings.length, tone: "var(--text)" },
  ];

  return (
    <div className="panel flex mb-6 divide-x" style={{ borderColor: "var(--hairline)" }}>
      {cols.map((c) => (
        <div key={c.label} className="flex-1 px-4 py-3" style={{ borderColor: "var(--hairline)" }}>
          <div className="mono text-2xl tabular-nums" style={{ color: c.tone }}>
            {c.value}
          </div>
          <div className="eyebrow mt-1">{c.label}</div>
        </div>
      ))}
    </div>
  );
}
