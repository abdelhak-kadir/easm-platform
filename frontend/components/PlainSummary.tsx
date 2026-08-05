import { Finding } from "../types/scan";
import { buildOverallSummary } from "../lib/explanations";

export default function PlainSummary({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  const { headline, points } = buildOverallSummary(findings);

  return (
    <div className="panel card-pad mb-6">
      <p className="eyebrow mb-2">Résumé en clair</p>
      <p className="text-[15px] font-bold mb-2" style={{ color: "var(--text-primary)" }}>
        {headline}
      </p>
      <ul className="text-sm space-y-1.5">
        {points.map((p, i) => (
          <li key={i} className="flex gap-2" style={{ color: "var(--text-secondary)" }}>
            <span style={{ color: "var(--brand-accent)" }}>•</span>
            <span>{p}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
