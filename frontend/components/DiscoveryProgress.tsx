"use client";

import { useState, useEffect, useCallback } from "react";
import { DiscoveryRunStatus } from "../types/scan";
import StatusBadge from "./StatusBadge";
import { formatElapsed } from "../lib/time";

type Props = {
  apiBase: string;
  runId: number;
  onRefreshAssets: () => void;
};

function isValidStatus(data: unknown): data is DiscoveryRunStatus {
  if (!data || typeof data !== "object") return false;
  const d = data as Record<string, unknown>;
  return (
    typeof d.id === "number" &&
    typeof d.round_number === "number" &&
    typeof d.max_rounds === "number" &&
    typeof d.status === "string" &&
    typeof d.assets === "object" &&
    d.assets !== null &&
    typeof (d.assets as Record<string, unknown>).total === "number"
  );
}

export default function DiscoveryProgress({ apiBase, runId, onRefreshAssets }: Props) {
  const [status, setStatus] = useState<DiscoveryRunStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [tick, setTick] = useState(0);

  const poll = useCallback(() => {
    fetch(`${apiBase}/scans/discovery/${runId}`)
      .then((res) => {
        if (!res.ok) {
          if (res.status === 404) setError("Run introuvable.");
          else setError(`Erreur serveur (${res.status}).`);
          return null;
        }
        return res.json();
      })
      .then((data) => {
        if (data === null) return;
        if (!isValidStatus(data)) {
          setError("Réponse inattendue du serveur.");
          return;
        }
        setError(null);
        setStatus(data);
      })
      .catch(() => {
        setError("Impossible de contacter le serveur.");
      });
  }, [apiBase, runId]);

  useEffect(() => {
    poll();
    const interval = setInterval(poll, 3000);
    return () => clearInterval(interval);
  }, [poll]);

  // Live tick for elapsed time while running
  useEffect(() => {
    if (!status || status.status !== "running") return;
    const interval = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(interval);
  }, [status?.status]);

  const cancelRun = useCallback(() => {
    setCancelling(true);
    fetch(`${apiBase}/scans/discovery/${runId}/cancel`, { method: "POST" })
      .then((res) => {
        if (!res.ok) {
          setError(`Échec de l'annulation (${res.status}).`);
          return;
        }
        poll();
      })
      .catch(() => {
        setError("Impossible d'annuler la découverte.");
      })
      .finally(() => setCancelling(false));
  }, [apiBase, runId, poll]);

  if (error) {
    return (
      <div
        className="panel px-4 py-3 mb-5 flex items-center gap-3"
        style={{ border: "1px solid var(--critical)" }}
      >
        <span className="text-xs font-semibold" style={{ color: "var(--critical)" }}>
          Erreur
        </span>
        <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
          {error}
        </span>
        <button onClick={poll} className="btn-primary text-xs shrink-0">
          Réessayer
        </button>
      </div>
    );
  }

  if (!status) return null;

  const done = status.status !== "running";
  const cancelled = status.status === "cancelled";
  const pct = status.assets.total > 0
    ? Math.round((status.assets.done / status.assets.total) * 100)
    : 0;

  return (
    <div
      className="panel mb-5"
      style={{
        border: `1px solid ${
          cancelled ? "var(--critical)" : done ? "var(--success)" : "var(--brand-accent)"
        }`,
      }}
    >
      {/* ── Compact bar (always visible) ─────────────────────────── */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left px-4 py-3 flex items-center gap-4 flex-wrap"
      >
        {/* Round indicator */}
        <div className="flex items-center gap-2 shrink-0">
          <span
            className="text-xs font-bold px-2 py-0.5 rounded-full"
            style={{
              color: cancelled ? "var(--critical)" : "var(--brand-accent)",
              background: cancelled ? "var(--critical-dim)" : "var(--brand-dim)",
            }}
          >
            Round {status.round_number}/{status.max_rounds}
          </span>
          {!done && <span className="status-dot status-dot--live" title="En cours" />}
        </div>

        {/* Progress bar (compact) */}
        <div className="flex-1 min-w-[80px] hidden sm:block">
          <div className="progress-track">
            <div
              className={`progress-fill ${!done && pct === 0 ? "progress-fill--indeterminate" : ""}`}
              style={{ width: done ? "100%" : `${Math.max(pct, 5)}%` }}
            />
          </div>
        </div>

        {/* Asset counts */}
        <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
          <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>
            {status.assets.total}
          </span>{" "}
          actif{status.assets.total !== 1 ? "s" : ""}
          {status.active_jobs > 0 && (
            <> · {status.active_jobs} scan{status.active_jobs !== 1 ? "s" : ""} en cours</>
          )}
        </span>

        {/* Elapsed time */}
        {status.created_at && !done && (
          <span className="text-[10px] shrink-0 tabular-nums" style={{ color: "var(--text-secondary)" }}>
            {formatElapsed(status.created_at)}
          </span>
        )}

        <StatusBadge status={status.status} pulsing={!done} />

        {/* Expand chevron */}
        <span
          className="text-[10px] shrink-0"
          style={{ color: "var(--text-secondary)" }}
        >
          {expanded ? "▴" : "▾"}
        </span>
      </button>

      {/* ── Expanded detail panel ────────────────────────────────── */}
      {expanded && (
        <div
          className="px-4 pb-4"
          style={{ borderTop: "1px solid var(--border)" }}
        >
          {/* Asset breakdown */}
          <div className="grid grid-cols-4 gap-3 mb-4 pt-3">
            {[
              { label: "Total", value: status.assets.total, color: "var(--text-primary)" },
              { label: "En attente", value: status.assets.pending, color: "var(--text-secondary)" },
              { label: "En cours", value: status.assets.running, color: "var(--high)" },
              { label: "Terminés", value: status.assets.done, color: "var(--success)" },
            ].map((s) => (
              <div key={s.label} className="text-center">
                <p
                  className="text-xl font-extrabold tabular-nums"
                  style={{ color: s.color, fontFamily: "var(--font-manrope)" }}
                >
                  {s.value}
                </p>
                <p className="text-[10px] font-medium uppercase mt-0.5" style={{ color: "var(--text-secondary)" }}>
                  {s.label}
                </p>
              </div>
            ))}
          </div>

          {/* Progress bar (full width) */}
          <div className="mb-4">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-medium uppercase" style={{ color: "var(--text-secondary)" }}>
                Progression
              </span>
              <span className="text-[10px] tabular-nums font-semibold" style={{ color: "var(--text-primary)" }}>
                {pct}%
              </span>
            </div>
            <div className="progress-track" style={{ height: 8, borderRadius: 4 }}>
              <div
                className="progress-fill"
                style={{
                  width: `${Math.max(pct, done ? 100 : 2)}%`,
                  height: 8,
                  borderRadius: 4,
                }}
              />
            </div>
          </div>

          {/* Round timeline */}
          <div className="mb-4">
            <p className="text-[10px] font-medium uppercase mb-2" style={{ color: "var(--text-secondary)" }}>
              Historique des rounds
            </p>
            <div className="flex items-center gap-1.5">
              {Array.from({ length: status.max_rounds }, (_, i) => {
                const rn = i + 1;
                const isPast = rn < status.round_number;
                const isCurrent = rn === status.round_number;
                const isFuture = rn > status.round_number;
                return (
                  <div key={rn} className="flex items-center gap-1.5">
                    <div
                      className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-extrabold shrink-0"
                      style={{
                        background: isPast
                          ? "var(--success)"
                          : isCurrent
                          ? cancelled
                            ? "var(--critical)"
                            : "var(--brand-accent)"
                          : "var(--panel-dim)",
                        color: isPast || isCurrent ? "#fff" : "var(--text-secondary)",
                        border: isFuture ? "1px solid var(--border)" : "none",
                      }}
                      title={isPast ? `Round ${rn} terminé` : isCurrent ? `Round ${rn} en cours` : `Round ${rn}`}
                    >
                      {isPast ? "✓" : rn}
                    </div>
                    {rn < status.max_rounds && (
                      <div
                        className="h-0.5 w-4 shrink-0"
                        style={{ background: isPast ? "var(--success)" : "var(--border)" }}
                      />
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Timestamps */}
          <div className="flex items-center gap-4 text-[10px] mb-4" style={{ color: "var(--text-secondary)" }}>
            {status.created_at && (
              <span>
                Début&nbsp;: {new Date(status.created_at).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}
              </span>
            )}
            {status.completed_at && (
              <span>
                Fin&nbsp;: {new Date(status.completed_at).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}
              </span>
            )}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2">
            {!done && (
              <button
                onClick={cancelRun}
                disabled={cancelling}
                className="text-[10px] font-semibold uppercase px-3 py-1 rounded-full shrink-0 transition-colors"
                style={{
                  color: "var(--critical)",
                  background: "var(--critical-dim)",
                  border: "1px solid var(--critical)",
                  opacity: cancelling ? 0.5 : 1,
                }}
              >
                {cancelling ? "..." : "Annuler la découverte"}
              </button>
            )}
            {done && (
              <button onClick={onRefreshAssets} className="btn-primary text-xs shrink-0">
                Actualiser les actifs
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
