import { Severity } from "../types/scan";
import { SEVERITY_HEX } from "./SeverityBadge";
import { findingTypeLabel, severityLabel } from "../lib/labels";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const URGENT: Severity[] = ["critical", "high"];
const ALL_SEVERITIES: Severity[] = [...SEVERITY_ORDER];

interface FindingsToolbarProps {
  search: string;
  onSearchChange: (v: string) => void;
  activeSeverities: Set<Severity>;
  onToggleSeverity: (s: Severity) => void;
  onSetSeverities: (s: Set<Severity>) => void;
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
  onSetSeverities,
  typeOptions,
  activeType,
  onTypeChange,
  resultCount,
  totalCount,
}: FindingsToolbarProps) {
  const isUrgentOnly =
    activeSeverities.size === URGENT.length && URGENT.every((s) => activeSeverities.has(s));
  const isAll = activeSeverities.size === ALL_SEVERITIES.length;

  return (
    <div className="mb-5 space-y-3">
      <div className="relative">
        <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-sm" style={{ color: "var(--text-secondary)" }}>
          ⌕
        </span>
        <input
          className="field-input pl-9"
          placeholder="Rechercher dans les résultats…"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={() => onSetSeverities(new Set(URGENT))}
          className="text-sm font-semibold px-3.5 py-1.5 rounded-full transition-colors"
          style={{
            border: `1px solid ${isUrgentOnly ? "var(--critical)" : "var(--border)"}`,
            color: isUrgentOnly ? "var(--critical)" : "var(--text-secondary)",
            background: isUrgentOnly ? "var(--critical-dim)" : "var(--panel)",
          }}
        >
          À corriger uniquement
        </button>
        <button
          onClick={() => onSetSeverities(new Set(ALL_SEVERITIES))}
          className="text-sm font-semibold px-3.5 py-1.5 rounded-full transition-colors"
          style={{
            border: `1px solid ${isAll ? "var(--brand-accent)" : "var(--border)"}`,
            color: isAll ? "var(--brand-accent)" : "var(--text-secondary)",
            background: isAll ? "var(--brand-dim)" : "var(--panel)",
          }}
        >
          Tout afficher
        </button>
      </div>

      <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
        Affichage de {resultCount} sur {totalCount} résultats
      </p>

      <details className="group">
        <summary className="cursor-pointer text-xs font-medium inline-flex items-center gap-1" style={{ color: "var(--brand-accent)" }}>
          Plus de filtres
        </summary>
        <div className="mt-3 space-y-3 pl-0.5">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="eyebrow mr-1">Gravité</span>
            {SEVERITY_ORDER.map((sev) => {
              const active = activeSeverities.has(sev);
              const color = SEVERITY_HEX[sev];
              return (
                <button
                  key={sev}
                  onClick={() => onToggleSeverity(sev)}
                  className="text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full transition-colors"
                  style={{
                    border: `1px solid ${active ? color : "var(--border)"}`,
                    color: active ? color : "var(--text-secondary)",
                    background: active ? `${color}14` : "var(--panel)",
                  }}
                >
                  {severityLabel(sev)}
                </button>
              );
            })}
          </div>

          {typeOptions.length > 1 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="eyebrow mr-1">Catégorie</span>
              <button
                onClick={() => onTypeChange(null)}
                className="text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full transition-colors"
                style={{
                  border: `1px solid ${activeType === null ? "var(--brand-accent)" : "var(--border)"}`,
                  color: activeType === null ? "var(--brand-accent)" : "var(--text-secondary)",
                  background: activeType === null ? "var(--brand-dim)" : "var(--panel)",
                }}
              >
                Toutes
              </button>
              {typeOptions.map((t) => (
                <button
                  key={t}
                  onClick={() => onTypeChange(t)}
                  className="text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full transition-colors"
                  style={{
                    border: `1px solid ${activeType === t ? "var(--brand-accent)" : "var(--border)"}`,
                    color: activeType === t ? "var(--brand-accent)" : "var(--text-secondary)",
                    background: activeType === t ? "var(--brand-dim)" : "var(--panel)",
                  }}
                >
                  {findingTypeLabel(t)}
                </button>
              ))}
            </div>
          )}
        </div>
      </details>
    </div>
  );
}
