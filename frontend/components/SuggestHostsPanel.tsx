"use client";

import { useState, useCallback, useEffect } from "react";
import {
  SuggestDiscoveredResponse,
  AcceptDiscoveredResponse,
} from "../types/scan";

interface Props {
  apiBase: string;
  jobId: number;
  onAssetsAccepted?: () => void;
}

type Phase = "loading" | "error" | "results" | "accepting" | "accepted";

function extractDetail(body: any): string {
  const detail = body?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    return detail.map((e: any) => e.msg || JSON.stringify(e)).join(" ; ");
  }
  return "";
}

export default function SuggestHostsPanel({ apiBase, jobId, onAssetsAccepted }: Props) {
  const [phase, setPhase] = useState<Phase>("loading");
  const [data, setData] = useState<SuggestDiscoveredResponse | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [acceptedResult, setAcceptedResult] = useState<AcceptDiscoveredResponse | null>(null);

  const load = useCallback(async () => {
    setPhase("loading");
    setError(null);

    let res: Response;
    try {
      res = await fetch(`${apiBase}/scans/${jobId}/suggest-discovered?category=hosts`);
    } catch {
      setError("Impossible de contacter le serveur. Vérifiez que le backend est accessible.");
      setPhase("error");
      return;
    }

    if (!res.ok) {
      let detail = "";
      try {
        detail = extractDetail(await res.json());
      } catch {
        // keep detail empty
      }
      setError(detail || `La récupération a échoué (${res.status}).`);
      setPhase("error");
      return;
    }

    const json: SuggestDiscoveredResponse = await res.json();
    setData(json);
    setPhase("results");
  }, [apiBase, jobId]);

  useEffect(() => {
    load();
  }, [load]);

  const toggleCandidate = useCallback((value: string, disabled: boolean) => {
    if (disabled) return;
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    if (!data) return;
    const eligible = data.candidates.filter((c) => !c.already_tracked);
    setSelected(new Set(eligible.map((c) => c.value)));
  }, [data]);

  const deselectAll = useCallback(() => setSelected(new Set()), []);

  const accept = useCallback(async () => {
    const values = [...selected];
    if (values.length === 0) return;

    setPhase("accepting");
    setError(null);

    let res: Response;
    try {
      res = await fetch(`${apiBase}/scans/suggest-discovered/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ values, asset_type: "subdomain" }),
      });
    } catch {
      setError("Impossible de contacter le serveur pendant l'acceptation.");
      setPhase("results");
      return;
    }

    if (!res.ok) {
      let detail = "";
      try {
        detail = extractDetail(await res.json());
      } catch {
        // keep detail empty
      }
      setError(detail || `L'acceptation a échoué (${res.status}).`);
      setPhase("results");
      return;
    }

    const json: AcceptDiscoveredResponse = await res.json();
    setAcceptedResult(json);
    setPhase("accepted");
    onAssetsAccepted?.();
  }, [apiBase, selected, onAssetsAccepted]);

  const reset = useCallback(() => {
    setSelected(new Set());
    setAcceptedResult(null);
    load();
  }, [load]);

  // ── loading ───────────────────────────────────────────────────────
  if (phase === "loading") {
    return (
      <div className="mb-6">
        <p className="eyebrow mb-2">Sous-domaines découverts</p>
        <div className="panel px-5 py-5 text-center">
          <p className="text-sm" style={{ color: "var(--muted)" }}>
            Chargement des résultats…
          </p>
        </div>
      </div>
    );
  }

  // ── error ─────────────────────────────────────────────────────────
  if (phase === "error") {
    return (
      <div className="mb-6">
        <p className="eyebrow mb-2">Sous-domaines découverts</p>
        <div
          className="panel px-5 py-4"
          style={{ borderColor: "var(--danger)", background: "var(--danger-dim)" }}
        >
          <p className="text-sm font-medium mb-2" style={{ color: "var(--danger)" }}>
            {error || "Une erreur est survenue."}
          </p>
          <button onClick={load} className="btn-ghost text-sm">
            Réessayer
          </button>
        </div>
      </div>
    );
  }

  if (!data) return null;
  const eligibleCount = data.candidates.filter((c) => !c.already_tracked).length;

  // ── accepted ──────────────────────────────────────────────────────
  if (phase === "accepted" && acceptedResult) {
    const createdCount = acceptedResult.created.filter((r) => r.created).length;
    const alreadyExisted = acceptedResult.created.length - createdCount;

    return (
      <div className="mb-6">
        <p className="eyebrow mb-2">Sous-domaines découverts</p>
        <div
          className="panel px-5 py-4"
          style={{ borderColor: "var(--success)", background: "var(--success-dim)" }}
        >
          <p className="text-sm font-semibold mb-1" style={{ color: "var(--success)" }}>
            {createdCount > 0
              ? `${createdCount} nouvelle${createdCount !== 1 ? "s" : ""} cible${createdCount !== 1 ? "s" : ""} ajoutée${createdCount !== 1 ? "s" : ""}`
              : "Aucune nouvelle cible ajoutée"}
            {alreadyExisted > 0 && (
              <span className="font-normal ml-1" style={{ color: "var(--muted)" }}>
                ({alreadyExisted} déjà suivie{alreadyExisted !== 1 ? "s" : ""})
              </span>
            )}
          </p>
          <ul className="text-xs mb-3 space-y-0.5" style={{ color: "var(--muted)" }}>
            {acceptedResult.created.map((r) => (
              <li key={r.asset_id} className="mono">
                {r.value}
                {r.created ? " — nouvelle cible, analyse lancée" : " — déjà suivie"}
              </li>
            ))}
          </ul>
          <button onClick={reset} className="btn-ghost text-sm">
            Actualiser
          </button>
        </div>
      </div>
    );
  }

  // ── results / accepting ──────────────────────────────────────────
  return (
    <div className="mb-6">
      <p className="eyebrow mb-2">Sous-domaines découverts</p>
      <div className="panel">
        <div
          className="flex flex-wrap items-center justify-between gap-2 px-5 py-3 border-b"
          style={{ borderColor: "var(--hairline)" }}
        >
          <p className="text-sm font-semibold">
            {data.candidates.length} hôte{data.candidates.length !== 1 ? "s" : ""} trouvé
            {data.candidates.length !== 1 ? "s" : ""}
            <span className="text-xs font-normal ml-1.5" style={{ color: "var(--muted)" }}>
              via énumération passive
            </span>
          </p>
          {eligibleCount > 0 && (
            <div className="flex items-center gap-2">
              <button
                onClick={selectAll}
                className="text-xs font-medium"
                style={{ color: "var(--signal)" }}
              >
                Tout sélectionner
              </button>
              <span style={{ color: "var(--hairline)" }}>·</span>
              <button
                onClick={deselectAll}
                className="text-xs font-medium"
                style={{ color: "var(--muted)" }}
              >
                Désélectionner
              </button>
            </div>
          )}
        </div>

        {data.candidates.length === 0 ? (
          <p className="px-5 py-6 text-sm text-center" style={{ color: "var(--muted)" }}>
            Aucun sous-domaine découvert pour cette cible.
          </p>
        ) : (
          <div
            className="divide-y"
            style={{ borderColor: "var(--hairline)", maxHeight: 320, overflowY: "auto" }}
          >
            {data.candidates.map((c) => (
              <label
                key={c.value}
                className={`flex items-center gap-3 px-5 py-2.5 transition-colors ${
                  c.already_tracked
                    ? "cursor-default"
                    : "cursor-pointer hover:bg-[var(--panel-alt)]"
                }`}
                style={{ opacity: c.already_tracked ? 0.55 : 1 }}
              >
                <input
                  type="checkbox"
                  checked={selected.has(c.value)}
                  disabled={c.already_tracked}
                  onChange={() => toggleCandidate(c.value, c.already_tracked)}
                  style={{ accentColor: "var(--signal)" }}
                />
                <span className="mono text-sm">{c.value}</span>
                {c.already_tracked && (
                  <span
                    className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full ml-auto"
                    style={{ color: "var(--muted)", background: "var(--panel-alt)" }}
                  >
                    DÉJÀ SUIVIE
                  </span>
                )}
              </label>
            ))}
          </div>
        )}

        {error && (
          <div
            className="px-4 py-2 mx-5 mb-3 rounded-md text-xs font-medium"
            style={{ color: "var(--danger)", background: "var(--danger-dim)" }}
          >
            {error}
          </div>
        )}

        {data.candidates.length > 0 && (
          <div
            className="flex items-center justify-end gap-2 px-5 py-3 border-t"
            style={{ borderColor: "var(--hairline)" }}
          >
            <button
              onClick={accept}
              disabled={selected.size === 0 || phase === "accepting"}
              className="btn-primary text-sm"
            >
              {phase === "accepting"
                ? "Ajout en cours…"
                : `Ajouter la sélection (${selected.size})`}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
