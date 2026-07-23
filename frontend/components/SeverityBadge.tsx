import { Severity } from "../types/scan";

export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#E0525C",
  high: "#E08A4B",
  medium: "#D9BB4C",
  low: "#5B8FBE",
  info: "#6B7785",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEVERITY_HEX[severity] || SEVERITY_HEX.info;
  return (
    <span
      className="mono text-[10px] tracking-wider px-1.5 py-0.5 border shrink-0"
      style={{ color, borderColor: color, backgroundColor: `${color}1a` }}
    >
      {severity.toUpperCase()}
    </span>
  );
}
