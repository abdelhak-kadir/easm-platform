import { Severity } from "../types/scan";
import { severityLabel } from "../lib/labels";

export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#C82014",
  high: "#D97706",
  medium: "#CA8A04",
  low: "#2563EB",
  info: "rgba(0, 0, 0, 0.58)",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEVERITY_HEX[severity] || SEVERITY_HEX.info;
  return (
    <span
      className="severity-pill"
      style={{ color, backgroundColor: `${severity === "info" ? "rgba(0,0,0,0.04)" : color + "14"}` }}
    >
      {severityLabel(severity).toUpperCase()}
    </span>
  );
}
