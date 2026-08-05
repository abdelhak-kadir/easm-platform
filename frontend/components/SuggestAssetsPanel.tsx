"use client";

import { useState, useCallback } from "react";
import { SuggestedAsset, SuggestAssetsResponse, AcceptSuggestedResponse } from "../types/scan";

interface Props {
  apiBase: string;
  jobId: number;
  onAssetsAccepted?: () => void;
}

type Phase = "idle" | "loading" | "error" | "results" | "accepting" | "accepted";
type SearchMode = "org" | "net";

/** FastAPI returns `detail` as either a plain string or an array of
 *  validation-error objects (`[{type, loc, msg, ...}]`).  Normalise
 *  both shapes to a single string so React can render it safely. */
function extractDetail(body: any): string {
  const detail = body?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    return detail.map((e: any) => e.msg || JSON.stringify(e)).join(" ; ");
  }
  return "";
}

export default function SuggestAssetsPanel({ apiBase, jobId, onAssetsAccepted }: Props) {
  const [mode, setMode] = useState<SearchMode | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [data, setData] = useState<SuggestAssetsResponse | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [acceptedResult, setAcceptedResult] = useState<AcceptSuggestedResponse | null>(null);

  const search = useCallback(
    async (by: SearchMode) => {
      setMode(by);
      setPhase("loading");
      setError(null);
      setData(null);
      setSelected(new Set());
      setAcceptedResult(null);

      let res: Response;
      try {
        res = await fetch(`${apiBase}/scans/${jobId}/suggest-assets?by=${by}`);
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
        setError(detail || `La recherche a échoué (${res.status}).`);
        setPhase("error");
        return;
      }

      const json: SuggestAssetsResponse = await res.json();
      setData(json);
      setPhase("results");
    },
    [apiBase, jobId]
  );

  const toggleCandidate = useCallback((ip: string, disabled: boolean) => {
    if (disabled) return;
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    if (!data) return;
    const eligible = data.candidates.filter((c) => !c.already_tracked && !c.is_source);
    setSelected(new Set(eligible.map((c) => c.ip)));
  }, [data]);

  const deselectAll = useCallback(() => {
    setSelected(new Set());
  }, []);

  const accept = useCallback(async () => {
    const ips = [...selected];
    if (ips.length === 0) return;

    setPhase("accepting");
    setError(null);

    let res: Response;
    try {
      res = await fetch(`${apiBase}/scans/suggest-assets/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips }),
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

    const json: AcceptSuggestedResponse = await res.json();
    setAcceptedResult(json);
    setPhase("accepted");
    onAssetsAccepted?.();
  }, [apiBase, selected, onAssetsAccepted]);

  const reset = useCallback(() => {
    setMode(null);
    setPhase("idle");
    setData(null);
    setSelected(new Set());
    setError(null);
    setAcceptedResult(null);
  }, []);

  const eligibleCount = data
    ? data.candidates.filter((c) => !c.already_tracked && !c.is_source).length
    : 0;

  // ── idle: mode selection ──────────────────────────────────────────
  if (phase === "idle") {
    return (
      <div className="mb-6">
        <p className="eyebrow mb-2">Adresses IP liées</p>
        <div className="panel px-5 py-4">
          <p className="text-sm mb-3" style={{ color: "var(--text-secondary)" }}>
            Découvrir d&apos;autres adresses IP appartenant potentiellement à la même
            organisation ou au même bloc réseau que cette cible.
          </p>
          <div className="flex flex-wrap gap-2">
            <button onClick={() => search("org")} className="btn-ghost text-sm">
              Par organisation
            </button>
            <button onClick={() => search("net")} className="btn-ghost text-sm">
              Par bloc réseau (/24)
            </button>
          </div>
          <p
            className="text-xs mt-2.5"
            style={{ color: "var(--text-secondary)" }}
          >
            Ces suggestions nécessitent une validation humaine elles ne sont pas
            ajoutées automatiquement.
          </p>
        </div>
      </div>
    );
  }

  // ── loading ───────────────────────────────────────────────────────
  if (phase === "loading") {
    return (
      <div className="mb-6">
        <p className="eyebrow mb-2">Adresses IP liées</p>
        <div className="panel px-5 py-5 text-center">
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Recherche en cours
            {mode === "org" ? " par organisation" : " par bloc réseau"}…
          </p>
          <div className="mt-3 flex justify-center">
            <span className="inline-block w-5 h-5 rounded-full border-2 animate-spin" style={{ borderColor: "var(--border)", borderTopColor: "var(--brand-accent)" }} />
          </div>
        </div>
      </div>
    );
  }

  // ── error ─────────────────────────────────────────────────────────
  if (phase === "error") {
    return (
      <div className="mb-6">
        <p className="eyebrow mb-2">Adresses IP liées</p>
        <div
          className="panel px-5 py-4"
          style={{ borderColor: "var(--critical)", background: "var(--critical-dim)" }}
        >
          <p className="text-sm font-medium mb-2" style={{ color: "var(--critical)" }}>
            {error || "Une erreur est survenue lors de la recherche."}
          </p>
          <div className="flex gap-2">
            <button onClick={reset} className="btn-ghost text-sm">
              Réessayer
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ── results ───────────────────────────────────────────────────────
  if (phase === "results" && data) {
    const candidates = data.candidates;

    return (
      <div className="mb-6">
        <p className="eyebrow mb-2">Adresses IP liées</p>

        {/* Shared hosting warning */}
        {data.is_shared_hosting_warning && (
          <div
            className="panel px-4 py-2.5 mb-2 text-xs font-medium flex items-start gap-2"
            style={{ borderColor: "var(--high)", background: "var(--high-dim)", color: "var(--high)" }}
          >
            <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9.66 16.5H2.34L12 3z" />
            </svg>
            <span>
              L&apos;organisation détectée correspond à un fournisseur de cloud ou
              d&apos;hébergement partagé. Les adresses IP partageant cette organisation
              n&apos;appartiennent probablement <strong>pas</strong> toutes à la même entité.
              Examinez chaque résultat avant de l&apos;accepter.
            </span>
          </div>
        )}

        <div className="panel">
          {/* Header */}
          <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-3 border-b" style={{ borderColor: "var(--border)" }}>
            <div>
              <p className="text-sm font-semibold">
                {candidates.length} IP trouvée{candidates.length !== 1 ? "s" : ""}
                <span className="text-xs font-normal ml-1.5" style={{ color: "var(--text-secondary)" }}>
                  {data.by === "org" ? `org: ${data.query_value}` : `net: ${data.query_value}`}
                </span>
              </p>
            </div>
            <div className="flex items-center gap-2">
              {eligibleCount > 0 && (
                <>
                  <button onClick={selectAll} className="text-xs font-medium" style={{ color: "var(--brand-accent)" }}>
                    Tout sélectionner
                  </button>
                  <span style={{ color: "var(--border)" }}>·</span>
                  <button onClick={deselectAll} className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                    Désélectionner
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Candidate list */}
          {candidates.length === 0 ? (
            <div className="px-5 py-6 text-center">
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                Aucune autre IP trouvée pour cette recherche.
              </p>
            </div>
          ) : (
            <div className="divide-y" style={{ borderColor: "var(--border)", maxHeight: 420, overflowY: "auto" }}>
              {candidates.map((c) => (
                <CandidateRow
                  key={c.ip}
                  candidate={c}
                  checked={selected.has(c.ip)}
                  onToggle={() => toggleCandidate(c.ip, c.already_tracked || c.is_source)}
                />
              ))}
            </div>
          )}

          {/* Error during accept */}
          {error && (
            <div
              className="px-4 py-2 mx-5 mb-3 rounded-md text-xs font-medium"
              style={{ color: "var(--critical)", background: "var(--critical-dim)" }}
            >
              {error}
            </div>
          )}

          {/* Action bar */}
          <div className="flex items-center justify-between gap-2 px-5 py-3 border-t" style={{ borderColor: "var(--border)" }}>
            <button onClick={reset} className="btn-ghost text-sm">
              Annuler
            </button>
            <button
              onClick={accept}
              disabled={selected.size === 0}
              className="btn-primary text-sm"
            >
              {`Accepter la sélection (${selected.size})`}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ── accepting (fallback, normally covered by results phase) ──────
  if (phase === "accepting") {
    return (
      <div className="mb-6">
        <p className="eyebrow mb-2">Adresses IP liées</p>
        <div className="panel px-5 py-5 text-center">
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Création des nouvelles cibles en cours…
          </p>
          <div className="mt-3 flex justify-center">
            <span className="inline-block w-5 h-5 rounded-full border-2 animate-spin" style={{ borderColor: "var(--border)", borderTopColor: "var(--brand-accent)" }} />
          </div>
        </div>
      </div>
    );
  }

  // ── accepted ──────────────────────────────────────────────────────
  if (phase === "accepted" && acceptedResult) {
    const createdCount = acceptedResult.created.filter((r) => r.created).length;
    const alreadyExisted = acceptedResult.created.length - createdCount;

    return (
      <div className="mb-6">
        <p className="eyebrow mb-2">Adresses IP liées</p>
        <div
          className="panel px-5 py-4"
          style={{ borderColor: "var(--success)", background: "var(--success-dim)" }}
        >
          <p className="text-sm font-semibold mb-1" style={{ color: "var(--success)" }}>
            {createdCount > 0
              ? `${createdCount} nouvelle${createdCount !== 1 ? "s" : ""} cible${createdCount !== 1 ? "s" : ""} ajoutée${createdCount !== 1 ? "s" : ""}`
              : "Aucune nouvelle cible ajoutée"}
            {alreadyExisted > 0 && (
              <span className="font-normal ml-1" style={{ color: "var(--text-secondary)" }}>
                ({alreadyExisted} déjà suivie{alreadyExisted !== 1 ? "s" : ""})
              </span>
            )}
          </p>
          <ul className="text-xs mb-3 space-y-0.5" style={{ color: "var(--text-secondary)" }}>
            {acceptedResult.created.map((r) => (
              <li key={r.asset_id} className="mono">
                {r.value}
                {r.created ? " nouvelle cible, analyse lancée" : " déjà suivie"}
              </li>
            ))}
          </ul>
          <button onClick={reset} className="btn-ghost text-sm">
            Nouvelle recherche
          </button>
        </div>
      </div>
    );
  }

  return null;
}

// ── Candidate row ───────────────────────────────────────────────────

function CandidateRow({
  candidate,
  checked,
  onToggle,
}: {
  candidate: SuggestedAsset;
  checked: boolean;
  onToggle: () => void;
}) {
  const disabled = candidate.already_tracked || candidate.is_source;

  return (
    <label
      className={`flex items-start gap-3 px-5 py-3 transition-colors ${
        disabled ? "cursor-default" : "cursor-pointer hover:bg-[var(--panel-dim)]"
      }`}
      style={{
        opacity: disabled ? 0.55 : 1,
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={onToggle}
        className="mt-0.5 shrink-0"
        style={{ accentColor: "var(--brand-accent)" }}
      />

      <div className="min-w-0 flex-1">
        {/* First line: IP + badges */}
        <div className="flex items-center gap-2 flex-wrap mb-0.5">
          <span className="mono text-sm font-semibold">{candidate.ip}</span>
          {candidate.is_source && (
            <span
              className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full"
              style={{ color: "var(--brand-accent)", background: "var(--brand-dim)" }}
            >
              CIBLE SOURCE
            </span>
          )}
          {candidate.already_tracked && (
            <span
              className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full"
              style={{ color: "var(--text-secondary)", background: "var(--panel-dim)" }}
            >
              DÉJÀ SUIVIE
            </span>
          )}
        </div>

        {/* Details */}
        <div className="text-xs space-y-0.5" style={{ color: "var(--text-secondary)" }}>
          {candidate.org && (
            <p>
              Organisation&nbsp;:{" "}
              <span style={{ color: "var(--text-primary)" }}>{candidate.org}</span>
            </p>
          )}
          {candidate.hostnames.length > 0 && (
            <p>
              Noms d&apos;hôte&nbsp;:{" "}
              <span style={{ color: "var(--text-primary)" }}>
                {candidate.hostnames.slice(0, 5).join(", ")}
                {candidate.hostnames.length > 5 && ` (+${candidate.hostnames.length - 5})`}
              </span>
            </p>
          )}
          {candidate.ports.length > 0 && (
            <p>
              Ports&nbsp;:{" "}
              <span style={{ color: "var(--text-primary)" }}>
                {candidate.ports.slice(0, 12).join(", ")}
                {candidate.ports.length > 12 && ` (+${candidate.ports.length - 12})`}
              </span>
            </p>
          )}
          {candidate.products.length > 0 && (
            <p>
              Produits&nbsp;:{" "}
              <span style={{ color: "var(--text-primary)" }}>
                {candidate.products.slice(0, 5).join(", ")}
                {candidate.products.length > 5 && ` (+${candidate.products.length - 5})`}
              </span>
            </p>
          )}
        </div>
      </div>
    </label>
  );
}
