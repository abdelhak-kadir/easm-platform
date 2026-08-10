import { Finding, AssetRisk } from "../types/scan";

interface RiskSummaryProps {
  findings: Finding[];
  risk: AssetRisk | null;
  assetValue: string;
}

function RiskGauge({ score }: { score: number }) {
  let color = "var(--success)";
  if (score >= 70) color = "var(--critical)";
  else if (score >= 40) color = "var(--high)";
  else if (score >= 15) color = "#CA8A04"; // medium yellow

  return (
    <div className="flex items-center gap-2 shrink-0">
      <svg width="44" height="44" viewBox="0 0 44 44" className="shrink-0">
        <circle
          cx="22" cy="22" r="18"
          fill="none"
          stroke="var(--border)"
          strokeWidth="4"
        />
        <circle
          cx="22" cy="22" r="18"
          fill="none"
          stroke={color}
          strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * 113} 113`}
          transform="rotate(-90 22 22)"
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
        <text
          x="22" y="22"
          textAnchor="middle"
          dominantBaseline="central"
          fontSize="11"
          fontWeight="800"
          fill="var(--text-primary)"
          fontFamily="var(--font-manrope)"
        >
          {score}
        </text>
      </svg>
    </div>
  );
}

export default function RiskSummary({ findings, risk, assetValue }: RiskSummaryProps) {
  const critical = risk?.breakdown?.critical ?? findings.filter((f) => f.severity === "critical").length;
  const high = risk?.breakdown?.high ?? findings.filter((f) => f.severity === "high").length;

  let tone: { bg: string; border: string; text: string; icon: string };
  let headline: string;
  let subline: string;

  if (findings.length === 0) {
    tone = { bg: "var(--success-dim)", border: "var(--success)", text: "var(--success)", icon: "✓" };
    headline = "Aucun résultat pour cette analyse.";
    subline = "Cette analyse n'a rien trouvé à examiner.";
  } else if (critical > 0) {
    tone = { bg: "var(--critical-dim)", border: "var(--critical)", text: "var(--critical)", icon: "!" };
    headline = `${critical} problème${critical === 1 ? "" : "s"} urgent${critical === 1 ? "" : "s"} sur ${assetValue}.`;
    subline = "Ces failles sont activement dangereuses et doivent être corrigées le plus vite possible.";
  } else if (high > 0) {
    tone = { bg: "var(--high-dim)", border: "var(--high)", text: "var(--high)", icon: "!" };
    headline = `${high} problème${high === 1 ? "" : "s"} à corriger prochainement sur ${assetValue}.`;
    subline = "Rien de critique, mais ce sont de vrais risques à traiter.";
  } else {
    tone = { bg: "var(--success-dim)", border: "var(--success)", text: "var(--success)", icon: "✓" };
    headline = `Aucun problème urgent détecté sur ${assetValue}.`;
    subline = `${findings.length} élément${findings.length === 1 ? "" : "s"} à examiner ci-dessous — aucun ne nécessite d'action immédiate.`;
  }

  return (
    <div
      className="rounded-xl px-5 py-4 mb-6 flex items-start gap-3"
      style={{ background: tone.bg, border: `1px solid ${tone.border}` }}
    >
      {risk && risk.finding_count > 0 ? (
        <RiskGauge score={risk.score} />
      ) : (
        <span
          className="w-6 h-6 rounded-full flex items-center justify-center text-sm font-bold shrink-0 mt-0.5"
          style={{ background: tone.text, color: "#fff" }}
        >
          {tone.icon}
        </span>
      )}
      <div className="flex-1 min-w-0">
        <p className="text-[15px] font-bold" style={{ color: "var(--text-primary)" }}>
          {headline}
        </p>
        <p className="text-sm mt-0.5" style={{ color: "var(--text-secondary)" }}>
          {subline}
        </p>
        {/* Risk detail chips */}
        {risk && risk.finding_count > 0 && (
          <div className="flex flex-wrap gap-2 mt-2">
            {risk.cve_count > 0 && (
              <span
                className="text-[10px] font-semibold px-2 py-0.5 rounded-full"
                style={{ color: "var(--critical)", background: "var(--critical-dim)" }}
              >
                {risk.cve_count} CVE{risk.cve_count !== 1 ? "s" : ""}
              </span>
            )}
            {risk.exposed_ports > 0 && (
              <span
                className="text-[10px] font-semibold px-2 py-0.5 rounded-full"
                style={{ color: "var(--high)", background: "var(--high-dim)" }}
              >
                {risk.exposed_ports} port{risk.exposed_ports !== 1 ? "s" : ""} exposé{risk.exposed_ports !== 1 ? "s" : ""}
              </span>
            )}
            {risk.last_scan && (
              <span className="text-[10px]" style={{ color: "var(--text-secondary)" }}>
                Dernière analyse : {new Date(risk.last_scan).toLocaleDateString("fr-FR")}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
