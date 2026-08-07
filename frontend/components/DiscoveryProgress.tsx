"use client";

import { useState, useEffect, useCallback } from "react";
import { DiscoveryRunStatus } from "../types/scan";

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

  const poll = useCallback(() => {
    fetch(`${apiBase}/scans/discovery/${runId}`)
      .then((res) => {
        if (!res.ok) {
          if (res.status === 404) {
            setError("Run introuvable.");
          } else {
            setError(`Erreur serveur (${res.status}).`);
          }
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

  return (
    <div
      className="panel px-4 py-3 mb-5 flex items-center gap-4 flex-wrap"
      style={{ border: "1px solid var(--brand-accent)" }}
    >
      {/* Round indicator */}
      <div className="flex items-center gap-2">
        <span
          className="text-xs font-bold px-2 py-0.5 rounded-full"
          style={{
            color: "var(--brand-accent)",
            background: "var(--brand-dim)",
          }}
        >
          Round {status.round_number}/{status.max_rounds}
        </span>
        {!done && (
          <span className="status-dot status-dot--live" title="En cours" />
        )}
      </div>

      {/* Asset counts */}
      <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
        <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>
          {status.assets.total}
        </span>{" "}
        actif{status.assets.total !== 1 ? "s" : ""} découvert{status.assets.total !== 1 ? "s" : ""}
        {status.active_jobs > 0 && (
          <> · {status.active_jobs} scan{status.active_jobs !== 1 ? "s" : ""} actif{status.active_jobs !== 1 ? "s" : ""}</>
        )}
      </span>

      {/* Status */}
      <span
        className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full"
        style={{
          color: done ? "var(--success)" : "var(--high)",
          background: done ? "var(--success-dim)" : "var(--high-dim)",
        }}
      >
        {done
          ? status.status === "completed"
            ? "Découverte terminée"
            : "Max rounds atteint"
          : "En cours"}
      </span>

      {/* Refresh button shown when the run is done */}
      {done && (
        <button onClick={onRefreshAssets} className="btn-primary text-xs shrink-0">
          Actualiser
        </button>
      )}
    </div>
  );
}
