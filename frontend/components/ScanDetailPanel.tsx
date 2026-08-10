"use client";

import { ScanJob, Finding, ScanResults } from "../types/scan";
import { toolLabel } from "../lib/labels";
import { timeAgo, formatElapsed } from "../lib/time";
import StatusBadge from "./StatusBadge";
import FindingCard from "./FindingCard";
import SeverityBadge from "./SeverityBadge";
import CopyButton from "./CopyButton";
import DiffViewer from "./DiffViewer";

interface Props {
  job: ScanJob;
  results: ScanResults | null;
  assetValue: string;
  apiBase: string;
}

export default function ScanDetailPanel({ job, results, assetValue, apiBase }: Props) {
  const isRunning = job.status === "running" || job.status === "pending";
  const isCompleted = job.status === "completed";
  const isFailed = job.status === "failed";

  // Compute duration
  let duration = "";
  if (job.started_at && job.completed_at) {
    const ms = new Date(job.completed_at).getTime() - new Date(job.started_at).getTime();
    const s = Math.floor(ms / 1000);
    if (s < 60) duration = `${s}s`;
    else if (s < 3600) duration = `${Math.floor(s / 60)}m ${s % 60}s`;
    else duration = `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  } else if (isRunning && job.started_at) {
    duration = formatElapsed(job.started_at);
  }

  const findings = results?.findings || [];

  // Group findings by type
  const byType: Record<string, Finding[]> = {};
  for (const f of findings) {
    (byType[f.finding_type] ||= []).push(f);
  }
  const typeGroups = Object.entries(byType).sort(
    (a, b) => b[1].length - a[1].length
  );

  // Severity counts
  const sevCounts: Record<string, number> = {};
  for (const f of findings) {
    sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
  }

  return (
    <div className="space-y-5">
      {/* ── Job metadata card ──────────────────────────────────── */}
      <div className="panel card-pad">
        <div className="flex items-center justify-between mb-3">
          <div>
            <p className="eyebrow mb-1">Détail de l'analyse</p>
            <h2 className="text-base font-bold" style={{ color: "var(--text-primary)" }}>
              {toolLabel(job.tool)}
            </h2>
            <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
              Cible&nbsp;: <span className="mono font-medium" style={{ color: "var(--text-primary)" }}>{assetValue}</span>
            </p>
          </div>
          <StatusBadge status={job.status} pulsing={isRunning} />
        </div>

        {/* Timing info */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          {job.created_at && (
            <div>
              <p className="font-medium uppercase text-[10px] tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
                Créée
              </p>
              <p className="mt-0.5 tabular-nums" style={{ color: "var(--text-primary)" }}>
                {new Date(job.created_at).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </p>
            </div>
          )}
          {job.started_at && (
            <div>
              <p className="font-medium uppercase text-[10px] tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
                Démarrée
              </p>
              <p className="mt-0.5 tabular-nums" style={{ color: "var(--text-primary)" }}>
                {new Date(job.started_at).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </p>
            </div>
          )}
          {job.completed_at && (
            <div>
              <p className="font-medium uppercase text-[10px] tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
                Terminée
              </p>
              <p className="mt-0.5 tabular-nums" style={{ color: "var(--text-primary)" }}>
                {new Date(job.completed_at).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </p>
            </div>
          )}
          {duration && (
            <div>
              <p className="font-medium uppercase text-[10px] tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
                Durée
              </p>
              <p className="mt-0.5 tabular-nums font-semibold" style={{ color: isRunning ? "var(--high)" : "var(--text-primary)" }}>
                {isRunning ? `${duration} (en cours)` : duration}
              </p>
            </div>
          )}
        </div>

        {/* Error message */}
        {isFailed && job.error_message && (
          <div
            className="mt-3 text-xs px-3 py-2 rounded-md"
            style={{ color: "var(--critical)", background: "var(--critical-dim)", border: "1px solid var(--critical)" }}
          >
            {job.error_message}
          </div>
        )}

        {/* Chain info */}
        {job.spawned_asset_value && (
          <div
            className="mt-3 text-xs px-3 py-2 rounded-md flex items-center gap-2"
            style={{ background: "var(--brand-dim)", border: "1px solid var(--brand-accent)" }}
          >
            <span style={{ color: "var(--brand-accent)" }}>→</span>
            <span style={{ color: "var(--text-primary)" }}>
              Scan chaîné&nbsp;:{" "}
              <span className="mono font-semibold">{job.spawned_asset_value}</span>
              {" "}· {toolLabel(job.spawned_job_tool || "")}
            </span>
            <StatusBadge status={job.spawned_job_status || "pending"} />
          </div>
        )}
      </div>

      {/* ── Findings summary ────────────────────────────────────── */}
      {findings.length > 0 && (
        <div className="panel card-pad">
          <p className="eyebrow mb-3">
            Résultats ({findings.length} trouvaille{findings.length !== 1 ? "s" : ""})
          </p>

          {/* Severity quick counts */}
          {Object.keys(sevCounts).length > 0 && (
            <div className="flex flex-wrap gap-2 mb-4">
              {(["critical", "high", "medium", "low", "info"] as const).map((s) => {
                const n = sevCounts[s];
                if (!n) return null;
                return (
                  <span
                    key={s}
                    className="severity-pill text-[11px]"
                  >
                    {n} <SeverityBadge severity={s} />
                  </span>
                );
              })}
            </div>
          )}

          {/* Findings grouped by type with scroll */}
          <div className="max-h-[60vh] overflow-y-auto space-y-3 pr-1">
            {findings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        </div>
      )}

      {/* Empty state for completed jobs with no findings */}
      {isCompleted && findings.length === 0 && (
        <div
          className="panel card-pad text-center"
          style={{ border: "1px dashed var(--border)" }}
        >
          <p className="text-sm font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
            Aucun résultat
          </p>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            Cette analyse n'a produit aucune donnée exploitable pour cette cible.
            {job.error_message && (
              <> <br />Détail&nbsp;: {job.error_message}</>
            )}
          </p>
        </div>
      )}

      {/* ── Version diff (completed jobs only) ──────────────────── */}
      {isCompleted && <DiffViewer apiBase={apiBase} assetId={job.asset_id} />}
    </div>
  );
}
