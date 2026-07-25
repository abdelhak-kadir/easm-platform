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
        <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-sm" style={{ color: "var(--faint)" }}>
          ⌕
        </span>
        <input
          className="field-input pl-9"
          placeholder="Search title, port, CVE, hostname…"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
        />
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="eyebrow mr-1">Severity</span>
        {SEVERITY_ORDER.map((sev) => {
          const active = activeSeverities.has(sev);
          const color = SEVERITY_HEX[sev];
          return (
            <button
              key={sev}
              onClick={() => onToggleSeverity(sev)}
              className="text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full transition-colors"
              style={{
                border: `1px solid ${active ? color : "var(--hairline)"}`,
                color: active ? color : "var(--muted)",
                background: active ? `${color}14` : "var(--panel)",
              }}
            >
              {sev}
            </button>
          );
        })}
      </div>

      {typeOptions.length > 1 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="eyebrow mr-1">Type</span>
          <button
            onClick={() => onTypeChange(null)}
            className="text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full transition-colors"
            style={{
              border: `1px solid ${activeType === null ? "var(--signal)" : "var(--hairline)"}`,
              color: activeType === null ? "var(--signal)" : "var(--muted)",
              background: activeType === null ? "var(--signal-dim)" : "var(--panel)",
            }}
          >
            All
          </button>
          {typeOptions.map((t) => (
            <button
              key={t}
              onClick={() => onTypeChange(t)}
              className="text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full transition-colors"
              style={{
                border: `1px solid ${activeType === t ? "var(--signal)" : "var(--hairline)"}`,
                color: activeType === t ? "var(--signal)" : "var(--muted)",
                background: activeType === t ? "var(--signal-dim)" : "var(--panel)",
              }}
            >
              {t.replace("_", " ")}
            </button>
          ))}
        </div>
      )}

      <p className="text-xs" style={{ color: "var(--muted)" }}>
        {resultCount} / {totalCount} findings
      </p>
    </div>
  );
}
