import { Finding } from "../types/scan";

interface RiskSummaryProps {
  findings: Finding[];
  assetValue: string;
}

export default function RiskSummary({ findings, assetValue }: RiskSummaryProps) {
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;

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
      <span
        className="w-6 h-6 rounded-full flex items-center justify-center text-sm font-bold shrink-0 mt-0.5"
        style={{ background: tone.text, color: "#fff" }}
      >
        {tone.icon}
      </span>
      <div>
        <p className="text-[15px] font-bold" style={{ color: "var(--text-primary)" }}>
          {headline}
        </p>
        <p className="text-sm mt-0.5" style={{ color: "var(--text-secondary)" }}>
          {subline}
        </p>
      </div>
    </div>
  );
}
