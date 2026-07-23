import { Severity } from "../types/scan";
import { SEVERITY_HEX } from "./SeverityBadge";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

interface FindingsToolbarProps {
  search: string;
  onSearchChange: (v: string) => void;
  activeSeverities: Set<Severity>;
  onToggleSeverity: (s: Severity) => void;
  typeOptions: string[];
  activeType: string | null;
  onTypeChange: (t: string | null) => void;
  resultCount: number;
  totalCount: number;
}

export default function FindingsToolbar({
  search,
  onSearchChange,
  activeSeverities,
  onToggleSeverity,
  typeOptions,
  activeType,
  onTypeChange,
  resultCount,
  totalCount,
}: FindingsToolbarProps) {
  return (
    <div className="mb-5 space-y-3">
      <div className="relative">
        <span className="mono absolute left-3 top-1/2 -translate-y-1/2 text-sm" style={{ color: "var(--muted)" }}>
          ⌕
        </span>
        <input
          className="field-input pl-8"
          placeholder="search title, port, cve, hostname…"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
        />
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="eyebrow mr-1">SEVERITY</span>
        {SEVERITY_ORDER.map((sev) => {
          const active = activeSeverities.has(sev);
          const color = SEVERITY_HEX[sev];
          return (
            <button
              key={sev}
              onClick={() => onToggleSeverity(sev)}
              className="mono text-[10px] uppercase tracking-wider px-2 py-1 border transition-colors"
              style={{
                borderColor: active ? color : "var(--hairline)",
                color: active ? color : "var(--muted)",
                background: active ? `${color}14` : "transparent",
              }}
            >
              {sev}
            </button>
          );
        })}
      </div>

      {typeOptions.length > 1 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="eyebrow mr-1">TYPE</span>
          <button
            onClick={() => onTypeChange(null)}
            className="mono text-[10px] uppercase tracking-wider px-2 py-1 border transition-colors"
            style={{
              borderColor: activeType === null ? "var(--signal)" : "var(--hairline)",
              color: activeType === null ? "var(--signal)" : "var(--muted)",
            }}
          >
            all
          </button>
          {typeOptions.map((t) => (
            <button
              key={t}
              onClick={() => onTypeChange(t)}
              className="mono text-[10px] uppercase tracking-wider px-2 py-1 border transition-colors"
              style={{
                borderColor: activeType === t ? "var(--signal)" : "var(--hairline)",
                color: activeType === t ? "var(--signal)" : "var(--muted)",
              }}
            >
              {t.replace("_", " ")}
            </button>
          ))}
        </div>
      )}

      <p className="mono text-xs" style={{ color: "var(--muted)" }}>
        {resultCount} / {totalCount} findings
      </p>
    </div>
  );
}
