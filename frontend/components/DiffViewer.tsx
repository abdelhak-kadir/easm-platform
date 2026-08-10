"use client";

import { useEffect, useState } from "react";
import { AssetDiffResponse, DiffEntry, DiffChangedKey } from "../types/scan";
import { toolLabel } from "../lib/labels";

interface Props {
  apiBase: string;
  assetId: number;
}

export default function DiffViewer({ apiBase, assetId }: Props) {
  const [data, setData] = useState<AssetDiffResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch(`${apiBase}/scans/asset/${assetId}/diff`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((json: AssetDiffResponse) => {
        if (!cancelled) setData(json);
      })
      .catch((e) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [apiBase, assetId]);

  if (loading) {
    return (
      <div className="panel card-pad">
        <p className="eyebrow mb-2">Différences entre versions</p>
        <div className="flex items-center gap-2 text-xs" style={{ color: "var(--text-secondary)" }}>
          <span className="inline-block w-3 h-3 rounded-full border-2 border-current border-t-transparent animate-spin" />
          Chargement des différences…
        </div>
      </div>
    );
  }

  if (error) {
    return null; // Silently hide — not every asset has multiple versions
  }

  if (!data || data.diffs.length === 0) {
    return null; // Nothing to show
  }

  return (
    <div className="panel card-pad">
      <p className="eyebrow mb-3">
        Différences entre versions ({data.diffs.length} outil{data.diffs.length !== 1 ? "s" : ""})
      </p>

      <div className="space-y-4">
        {data.diffs.map((diff) => (
          <DiffCard key={diff.tool} diff={diff} />
        ))}
      </div>
    </div>
  );
}

/* ── Per-tool diff card ─────────────────────────────────────────────── */

function DiffCard({ diff }: { diff: DiffEntry }) {
  const hasChanges =
    diff.added_keys.length > 0 ||
    diff.removed_keys.length > 0 ||
    diff.changed_keys.length > 0;

  if (!hasChanges) {
    return (
      <div
        className="rounded-lg px-4 py-3 text-xs"
        style={{ background: "var(--success-dim)", border: "1px solid var(--success)" }}
      >
        <span className="font-semibold" style={{ color: "var(--text-primary)" }}>
          {toolLabel(diff.tool)}
        </span>{" "}
        <span style={{ color: "var(--text-secondary)" }}>
          v{diff.previous_version} → v{diff.latest_version} : aucun changement
        </span>
      </div>
    );
  }

  return (
    <div
      className="rounded-lg px-4 py-3"
      style={{ background: "var(--panel-dim)", border: "1px solid var(--border)" }}
    >
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <span
          className="text-[11px] font-semibold uppercase tracking-[0.04em] px-2 py-0.5 rounded"
          style={{ color: "var(--brand-accent)", background: "var(--brand-dim)" }}
        >
          {toolLabel(diff.tool)}
        </span>
        <span className="text-[11px] mono" style={{ color: "var(--text-secondary)" }}>
          v{diff.previous_version} → v{diff.latest_version}
        </span>
      </div>

      {/* Added keys */}
      {diff.added_keys.length > 0 && (
        <div className="mb-2">
          <span
            className="text-[10px] font-semibold uppercase tracking-[0.04em]"
            style={{ color: "var(--success)" }}
          >
            +{diff.added_keys.length} ajouté{diff.added_keys.length !== 1 ? "s" : ""}
          </span>
          <div className="flex flex-wrap gap-1 mt-1">
            {diff.added_keys.map((key) => (
              <span
                key={key}
                className="text-[11px] mono px-2 py-0.5 rounded"
                style={{ color: "var(--success)", background: "var(--success-dim)" }}
              >
                {key}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Removed keys */}
      {diff.removed_keys.length > 0 && (
        <div className="mb-2">
          <span
            className="text-[10px] font-semibold uppercase tracking-[0.04em]"
            style={{ color: "var(--critical)" }}
          >
            −{diff.removed_keys.length} retiré{diff.removed_keys.length !== 1 ? "s" : ""}
          </span>
          <div className="flex flex-wrap gap-1 mt-1">
            {diff.removed_keys.map((key) => (
              <span
                key={key}
                className="text-[11px] mono px-2 py-0.5 rounded"
                style={{ color: "var(--critical)", background: "var(--critical-dim)" }}
              >
                {key}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Changed keys */}
      {diff.changed_keys.length > 0 && (
        <div>
          <span
            className="text-[10px] font-semibold uppercase tracking-[0.04em]"
            style={{ color: "var(--high)" }}
          >
            ~{diff.changed_keys.length} modifié{diff.changed_keys.length !== 1 ? "s" : ""}
          </span>
          <div className="mt-1 space-y-1">
            {diff.changed_keys.map((ck) => (
              <ChangedKeyRow key={ck.key} changed={ck} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Single changed-key row ─────────────────────────────────────────── */

function ChangedKeyRow({ changed }: { changed: DiffChangedKey }) {
  return (
    <div className="text-[11px] ml-1">
      <span className="mono font-semibold" style={{ color: "var(--text-primary)" }}>
        {changed.key}
      </span>

      {/* List diff: items added / removed */}
      {"added_items" in changed || "removed_items" in changed ? (
        <div className="ml-3 mt-0.5 space-y-0.5">
          {changed.removed_items && changed.removed_items.length > 0 && (
            <div className="flex items-start gap-1">
              <span style={{ color: "var(--critical)", fontWeight: 700 }}>−</span>
              <span style={{ color: "var(--critical)" }}>
                {changed.removed_items.join(", ")}
              </span>
            </div>
          )}
          {changed.added_items && changed.added_items.length > 0 && (
            <div className="flex items-start gap-1">
              <span style={{ color: "var(--success)", fontWeight: 700 }}>+</span>
              <span style={{ color: "var(--success)" }}>
                {changed.added_items.join(", ")}
              </span>
            </div>
          )}
        </div>
      ) : (
        /* Scalar diff: old → new */
        <div className="ml-3 mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span
            className="mono px-1.5 py-0.5 rounded line-through"
            style={{ color: "var(--critical)", background: "var(--critical-dim)" }}
          >
            {String(changed.old ?? "∅")}
          </span>
          <span style={{ color: "var(--text-secondary)" }}>→</span>
          <span
            className="mono px-1.5 py-0.5 rounded"
            style={{ color: "var(--success)", background: "var(--success-dim)" }}
          >
            {String(changed.new ?? "∅")}
          </span>
        </div>
      )}
    </div>
  );
}
