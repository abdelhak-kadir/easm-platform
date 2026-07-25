import { Severity } from "../types/scan";

export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#D92D20",
  high: "#DC6803",
  medium: "#CA8A04",
  low: "#2563EB",
  info: "#667085",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEVERITY_HEX[severity] || SEVERITY_HEX.info;
  return (
    <span
      className="text-[11px] font-semibold tracking-wide px-2 py-1 rounded-full shrink-0"
      style={{ color, backgroundColor: `${color}14` }}
    >
      {severity.toUpperCase()}
    </span>
  );
}
