"use client";

import { useState, useMemo, useEffect } from "react";
import { Asset, ScanJob } from "../types/scan";

const TYPE_LABEL: Record<string, string> = {
  domain: "Domaine",
  subdomain: "Sous-domaine",
  ip: "IP",
};

type Props = {
  assets: Asset[];
  selectedAssetId?: number | null;
  activeScanCount: number;
  fleetJobs: ScanJob[];
  onSelect: (asset: Asset) => void;
  onCreate: (value: string, assetType?: string) => Promise<Asset>;
};

/** Compute per-asset status dot color and active state from asset.status + fleet jobs. */
function assetDotInfo(
  asset: Asset,
  fleetJobs: ScanJob[]
): { color: string; pulsing: boolean; label: string } {
  const assetJobs = fleetJobs.filter((j: any) => j.asset_id === asset.id);
  const hasActive = assetJobs.some((j) => j.status === "running" || j.status === "pending");

  if (hasActive) {
    return { color: "var(--brand-accent)", pulsing: true, label: "Scan en cours" };
  }
  if (asset.status === "done") {
    const hasFailed = assetJobs.some((j) => j.status === "failed");
    if (hasFailed) return { color: "var(--critical)", pulsing: false, label: "Échec" };
    return { color: "var(--success)", pulsing: false, label: "Terminé" };
  }
  if (asset.status === "running") {
    return { color: "var(--brand-accent)", pulsing: true, label: "En cours" };
  }
  // pending — no scans run yet
  return { color: "rgba(0,0,0,0.30)", pulsing: false, label: "En attente" };
}

export default function Sidebar({
  assets,
  selectedAssetId,
  activeScanCount,
  fleetJobs,
  onSelect,
  onCreate,
}: Props) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState("");
  const [highlightIndex, setHighlightIndex] = useState(0);

  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of assets) counts[a.asset_type] = (counts[a.asset_type] || 0) + 1;
    return counts;
  }, [assets]);

  const filtered = useMemo(() => {
    let list = assets;
    if (filter) list = list.filter((a) => a.asset_type === filter);
    if (query) list = list.filter((a) => a.value.toLowerCase().includes(query.toLowerCase()));
    return list;
  }, [assets, filter, query]);

  // Clamp highlight index when filtered list changes
  useEffect(() => {
    setHighlightIndex((prev) => Math.min(prev, Math.max(0, filtered.length - 1)));
  }, [filtered.length]);

  async function handleCreate() {
    const value = query.trim();
    if (!value) return;
    setError("");
    setAdding(true);
    try {
      const asset = await onCreate(value);
      setQuery("");
      onSelect(asset);
    } catch (e: any) {
      setError(e.message || "Erreur lors de l'ajout");
    } finally {
      setAdding(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") handleCreate();
    if (e.key === "Escape") setQuery("");
  }

  // ── Keyboard shortcuts ──────────────────────────────────────────
  useEffect(() => {
    function handler(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement)?.tagName;
      const isEditing = (e.target as HTMLElement)?.isContentEditable;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || isEditing) {
        // In the sidebar search input: Escape clears the query
        if (e.key === "Escape" && document.activeElement?.getAttribute("id") === "asset-search-input") {
          setQuery("");
        }
        return;
      }

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setHighlightIndex((prev) => Math.min(prev + 1, Math.max(0, filtered.length - 1)));
      }
      if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setHighlightIndex((prev) => Math.max(0, prev - 1));
      }
      if (e.key === "Enter" && filtered.length > 0) {
        e.preventDefault();
        onSelect(filtered[highlightIndex]);
      }
      if (e.key === "Escape") {
        e.preventDefault();
        onSelect(null as any); // deselect asset
        setHighlightIndex(0);
      }
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        const input = document.getElementById("asset-search-input");
        input?.focus();
      }
    }

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [filtered, highlightIndex, onSelect]);

  // Scroll highlighted item into view
  useEffect(() => {
    const el = document.getElementById(`asset-row-${filtered[highlightIndex]?.id}`);
    el?.scrollIntoView({ block: "nearest" });
  }, [highlightIndex, filtered]);

  return (
    <aside
      className="flex flex-col h-full"
      style={{
        background: "var(--panel)",
        borderRight: "1px solid var(--border)",
      }}
    >
      {/* Brand header */}
      <div
        className="px-5 py-4 flex items-center gap-3"
        style={{ borderBottom: "1px solid var(--border)" }}
      >
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center text-white text-xs font-extrabold shrink-0"
          style={{ background: "var(--brand-accent)" }}
        >
          E
        </div>
        <div>
          <p className="text-[15px] font-bold leading-none" style={{ color: "var(--text-primary)" }}>
            EASM
          </p>
          <p className="text-[10px] leading-none mt-0.5" style={{ color: "var(--text-secondary)" }}>
            Attack Surface
          </p>
        </div>
      </div>

      {/* Search + add */}
      <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="flex gap-2">
          <input
            id="asset-search-input"
            className="field-input flex-1"
            placeholder="Ajouter un domaine ou IP..."
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setError("");
            }}
            onKeyDown={handleKeyDown}
          />
          <button
            onClick={handleCreate}
            disabled={adding || !query.trim()}
            className="btn-primary shrink-0"
            style={{ padding: "8px 14px" }}
          >
            {adding ? "…" : "Ajouter"}
          </button>
        </div>
        {error && (
          <p className="text-[11px] mt-1.5" style={{ color: "var(--critical)" }}>
            {error}
          </p>
        )}
      </div>

      {/* Type filter pills */}
      <div className="px-4 py-2.5 flex items-center gap-1.5 flex-wrap">
        {[
          { key: null, label: "Tout", count: assets.length },
          { key: "domain", label: "Domaines", count: typeCounts["domain"] || 0 },
          { key: "subdomain", label: "Sous-domaines", count: typeCounts["subdomain"] || 0 },
          { key: "ip", label: "IPs", count: typeCounts["ip"] || 0 },
        ].map(({ key, label, count }) => {
          const active = filter === key;
          return (
            <button
              key={key ?? "all"}
              onClick={() => {
                setFilter(key as string | null);
                setHighlightIndex(0);
              }}
              className="text-[11px] font-semibold px-2.5 py-1 rounded-full transition-all duration-200"
              style={{
                border: `1px solid ${active ? "var(--brand-accent)" : "var(--border)"}`,
                color: active ? "var(--brand-accent)" : "var(--text-secondary)",
                background: active ? "var(--brand-dim)" : "transparent",
                cursor: "pointer",
              }}
            >
              {label} <span className="opacity-60 ml-0.5">{count}</span>
            </button>
          );
        })}
      </div>

      {/* Asset list */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="px-4 py-12 text-center">
            <p
              className="text-xs mb-3"
              style={{ color: "var(--text-secondary)" }}
            >
              {assets.length === 0
                ? "Ajoutez votre première cible ci-dessus"
                : "Aucune cible ne correspond"}
            </p>
            {assets.length === 0 && (
              <div className="text-[11px] space-y-1" style={{ color: "var(--text-secondary)" }}>
                <p>1. Saisissez un domaine ou une adresse IP</p>
                <p>2. Appuyez sur Entrée ou sur Ajouter</p>
                <p>3. Lancez une analyse rapide ou une découverte</p>
              </div>
            )}
          </div>
        ) : (
          <div className="py-1">
            {filtered.map((a, idx) => {
              const active = a.id === selectedAssetId;
              const highlighted = idx === highlightIndex;
              const dot = assetDotInfo(a, fleetJobs);
              return (
                <button
                  key={a.id}
                  id={`asset-row-${a.id}`}
                  onClick={() => onSelect(a)}
                  className="w-full text-left px-4 py-2.5 flex items-center gap-2.5 transition-colors"
                  style={{
                    background: active
                      ? "var(--brand-dim)"
                      : highlighted
                      ? "var(--panel-dim)"
                      : "transparent",
                    borderLeft: `3px solid ${
                      active ? "var(--brand-accent)" : highlighted ? "var(--border)" : "transparent"
                    }`,
                  }}
                  onMouseEnter={(e) => {
                    if (!active) e.currentTarget.style.background = "var(--panel-dim)";
                  }}
                  onMouseLeave={(e) => {
                    if (!active) e.currentTarget.style.background = "transparent";
                  }}
                >
                  {/* Status dot */}
                  <span
                    className="shrink-0"
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: dot.color,
                      display: "inline-block",
                    }}
                    title={dot.label}
                  />
                  {dot.pulsing && (
                    <span
                      className="status-dot status-dot--live shrink-0"
                      style={{ marginLeft: -18 }}
                      title={dot.label}
                    />
                  )}

                  <span
                    className="mono text-[13px] truncate flex-1 font-medium"
                    style={{ color: "var(--text-primary)" }}
                  >
                    {a.value}
                  </span>
                  <span
                    className="text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded-full shrink-0"
                    style={{
                      color: "var(--text-secondary)",
                      background: "var(--panel-dim)",
                      border: "1px solid var(--border)",
                    }}
                  >
                    {TYPE_LABEL[a.asset_type] || a.asset_type}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Bottom stats */}
      <div
        className="px-4 py-3 flex items-center justify-between text-[11px] font-medium"
        style={{
          borderTop: "1px solid var(--border)",
          color: "var(--text-secondary)",
        }}
      >
        <span>
          {assets.length} cible{assets.length !== 1 ? "s" : ""}
        </span>
        {activeScanCount > 0 && (
          <span className="flex items-center gap-1.5" style={{ color: "var(--brand-accent)" }}>
            <span className="status-dot status-dot--live" />
            {activeScanCount} actif{activeScanCount !== 1 ? "s" : ""}
          </span>
        )}
        <span
          className="text-[10px] cursor-help"
          title="Raccourcis : j/k naviguer, Entrée sélectionner, Échap désélectionner, Ctrl+K rechercher"
          style={{ color: "var(--text-secondary)", opacity: 0.5 }}
        >
          ?
        </span>
      </div>
    </aside>
  );
}
