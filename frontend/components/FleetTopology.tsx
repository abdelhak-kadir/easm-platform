"use client";

import { useMemo, useState } from "react";
import { Asset } from "../types/scan";

/* ── Types ──────────────────────────────────────────────────────────── */

// Minimal job shape: only what the per-asset status needs. FleetDashboard's
// FleetJob[] is structurally compatible.
interface FleetJobLite {
  id: number;
  asset_id: number;
  status: string;
}

interface Props {
  assets: Asset[];
  jobs: FleetJobLite[];
  onSelectAsset: (id: number) => void;
}

/* ── Status → visuals (same palette as TopologyMap) ────────────────── */

function statusAccent(status: string | null): string {
  switch (status) {
    case "completed": return "var(--success)";
    case "running": return "var(--high)";
    case "pending": return "var(--text-secondary)";
    case "failed": return "var(--critical)";
    default: return "var(--border)";
  }
}

function statusFr(status: string | null): string {
  switch (status) {
    case "completed": return "Terminé";
    case "running": return "En cours";
    case "pending": return "En attente";
    case "failed": return "Échec";
    default: return "Aucun scan";
  }
}

const typeEmoji: Record<string, string> = {
  domain: "🌐",
  subdomain: "🔗",
  ip: "🖥",
  email: "📧",
  service: "⚡",
  technology: "📊",
};

// Display order for members within a group (subdomains first).
const typeOrder = ["subdomain", "ip", "email", "service", "technology", "domain"];

interface Group {
  root: Asset | null;
  members: Asset[];
  label: string;
}

/* ── Component ──────────────────────────────────────────────────────── */

export default function FleetTopology({ assets, jobs, onSelectAsset }: Props) {
  const [search, setSearch] = useState("");

  // Latest job (highest id) per asset → current status.
  const latestStatus = useMemo(() => {
    const m = new Map<number, { id: number; status: string }>();
    for (const j of jobs) {
      const cur = m.get(j.asset_id);
      if (!cur || j.id > cur.id) m.set(j.asset_id, { id: j.id, status: j.status });
    }
    return m;
  }, [jobs]);

  // Group every asset under its root domain (root_asset_id), a domain
  // being its own root unless it is itself linked under another domain.
  // Assets with no resolvable root land in the "Non groupés" bucket.
  const groups = useMemo<Group[]>(() => {
    const byId = new Map<number, Asset>(assets.map((a) => [a.id, a]));
    const buckets = new Map<string, { root: Asset | null; members: Asset[] }>();

    for (const a of assets) {
      let key: string;
      if (a.asset_type === "domain") {
        const linked = a.root_asset_id != null && byId.has(a.root_asset_id);
        key = linked ? `root-${a.root_asset_id}` : `root-${a.id}`;
      } else {
        const linked = a.root_asset_id != null && byId.has(a.root_asset_id);
        key = linked ? `root-${a.root_asset_id}` : "ungrouped";
      }
      if (!buckets.has(key)) {
        const rootId = key.startsWith("root-") ? Number(key.slice(5)) : null;
        const root = rootId !== null ? (byId.get(rootId) ?? null) : null;
        buckets.set(key, { root, members: [] });
      }
      const bucket = buckets.get(key)!;
      // The root asset itself is not its own member.
      if (bucket.root && bucket.root.id === a.id) continue;
      bucket.members.push(a);
    }

    const sortMembers = (members: Asset[]) =>
      [...members].sort((x, y) => {
        const tx = typeOrder.indexOf(x.asset_type) === -1 ? typeOrder.length : typeOrder.indexOf(x.asset_type);
        const ty = typeOrder.indexOf(y.asset_type) === -1 ? typeOrder.length : typeOrder.indexOf(y.asset_type);
        if (tx !== ty) return tx - ty;
        return x.value.localeCompare(y.value);
      });

    const result: Group[] = [];
    for (const { root, members } of buckets.values()) {
      result.push({
        root,
        members: sortMembers(members),
        label: root ? root.value : "Non groupés",
      });
    }
    // Rooted groups first (alphabetical), ungrouped last.
    return result.sort((a, b) => {
      if (a.root && !b.root) return -1;
      if (!a.root && b.root) return 1;
      return a.label.localeCompare(b.label);
    });
  }, [assets]);

  if (assets.length === 0) return null;

  const q = search.trim().toLowerCase();
  const visibleGroups = q
    ? groups
        .map((g) => ({
          ...g,
          members: g.members.filter((m) => m.value.toLowerCase().includes(q)),
        }))
        .filter((g) => g.label.toLowerCase().includes(q) || g.members.length > 0)
    : groups;

  const totalMembers = visibleGroups.reduce((n, g) => n + g.members.length, 0);

  return (
    <div className="panel overflow-hidden">
      {/* ── Header ──────────────────────────────────────────────── */}
      <div
        className="px-5 py-3 flex items-center justify-between gap-3 flex-wrap"
        style={{ borderBottom: "1px solid var(--border)" }}
      >
        <p className="eyebrow" style={{ marginBottom: 0 }}>Topologie globale</p>
        <div className="flex items-center gap-3 flex-wrap">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filtrer…"
            className="text-[11px] px-2 py-1 rounded"
            style={{
              background: "var(--panel-dim)",
              border: "1px solid var(--border)",
              color: "var(--text-primary)",
              outline: "none",
              width: 140,
            }}
          />
          <span className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
            {visibleGroups.length} domaine{visibleGroups.length !== 1 ? "s" : ""} · {totalMembers} actif{totalMembers !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      {/* ── Groups ──────────────────────────────────────────────── */}
      <div className="divide-y" style={{ borderColor: "var(--border)" }}>
        {visibleGroups.map((g) => {
          const activeCount = g.members.filter((m) => {
            const st = latestStatus.get(m.id)?.status;
            return st === "running" || st === "pending";
          }).length;
          const rootStatus = g.root ? (latestStatus.get(g.root.id)?.status ?? null) : null;
          return (
            <div key={g.label}>
              {/* Root row */}
              {g.root && (
                <button
                  onClick={() => onSelectAsset(g.root!.id)}
                  className="w-full flex items-center gap-2 px-5 py-2.5 hover:opacity-80 text-left"
                  style={{ background: "var(--panel-dim)" }}
                >
                  <span style={{ fontSize: "15px" }}>{typeEmoji[g.root.asset_type] ?? "•"}</span>
                  <span className="mono text-sm font-bold flex-1 truncate" style={{ color: "var(--text-primary)" }}>
                    {g.root.value}
                  </span>
                  <span
                    className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                    style={{ color: "var(--brand-accent)", background: "var(--brand-dim)", border: "1px solid var(--brand-accent)" }}
                  >
                    Root
                  </span>
                  {rootStatus && (
                    <span className="text-[10px] font-semibold" style={{ color: statusAccent(rootStatus) }}>
                      {statusFr(rootStatus)}
                    </span>
                  )}
                  <span className="text-[10px]" style={{ color: "var(--text-secondary)" }}>
                    {g.members.length} actif{g.members.length !== 1 ? "s" : ""}
                    {activeCount > 0 ? ` · ${activeCount} en cours` : ""}
                  </span>
                </button>
              )}
              {/* Ungrouped header */}
              {!g.root && (
                <div className="flex items-center gap-2 px-5 py-2.5" style={{ background: "var(--panel-dim)" }}>
                  <span style={{ fontSize: "15px" }}>🧩</span>
                  <span className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>Non groupés</span>
                  <span className="text-[10px]" style={{ color: "var(--text-secondary)" }}>
                    {g.members.length} actif{g.members.length !== 1 ? "s" : ""} sans domaine racine
                  </span>
                </div>
              )}
              {/* Member rows */}
              {g.members.length === 0 && (
                <p className="px-5 py-2.5 text-xs" style={{ color: "var(--text-secondary)" }}>
                  Aucun actif lié.
                </p>
              )}
              {g.members.map((m, i) => {
                const st = latestStatus.get(m.id)?.status ?? null;
                const accent = statusAccent(st);
                const last = i === g.members.length - 1;
                return (
                  <button
                    key={m.id}
                    onClick={() => onSelectAsset(m.id)}
                    className="w-full flex items-center gap-2 px-5 py-2 text-left hover:opacity-80"
                    style={{ borderLeft: `3px solid ${accent}`, paddingLeft: "28px" }}
                  >
                    <span className="mono text-[10px]" style={{ color: "var(--text-faint)", width: 14 }}>
                      {last ? "└─" : "├─"}
                    </span>
                    <span style={{ fontSize: "13px" }}>{typeEmoji[m.asset_type] ?? "•"}</span>
                    <span className="mono text-xs font-semibold flex-1 truncate" style={{ color: "var(--text-primary)" }}>
                      {m.value}
                    </span>
                    <span
                      className="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded"
                      style={{ color: "var(--text-secondary)", background: "var(--panel-dim)", border: "1px solid var(--border)" }}
                    >
                      {m.asset_type}
                    </span>
                    <span className="text-[10px] font-semibold" style={{ color: accent }}>
                      {statusFr(st)}
                    </span>
                  </button>
                );
              })}
            </div>
          );
        })}
      </div>
    </div>
  );
}
