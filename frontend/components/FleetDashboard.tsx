"use client";

import { Asset, ScanJob } from "../types/scan";
import { toolLabel } from "../lib/labels";
import { timeAgo } from "../lib/time";

interface FleetJob extends ScanJob {
  asset_id: number;
  asset_value: string;
}

const STATUS_PILL: Record<string, { color: string; bg: string; label: string }> = {
  completed: { color: "var(--success)", bg: "var(--success-dim)", label: "OK" },
  failed: { color: "var(--critical)", bg: "var(--critical-dim)", label: "Échec" },
  running: { color: "var(--high)", bg: "var(--high-dim)", label: "Actif" },
  pending: { color: "var(--text-secondary)", bg: "var(--panel-dim)", label: "Queue" },
};

type Props = {
  assets: Asset[];
  jobs: FleetJob[];
  activeCount: number;
  onSelectAsset: (id: number) => void;
};

export default function FleetDashboard({ assets, jobs, activeCount, onSelectAsset }: Props) {
  const completed = jobs.filter((j) => j.status === "completed").length;
  const failed = jobs.filter((j) => j.status === "failed").length;
  const domains = assets.filter((a) => a.asset_type === "domain").length;
  const subs = assets.filter((a) => a.asset_type === "subdomain").length;
  const ips = assets.filter((a) => a.asset_type === "ip").length;

  const statTiles = [
    { label: "Cibles", value: assets.length, subtitle: `${domains} domaines · ${subs} sous-domaines · ${ips} IPs` },
    { label: "Scans actifs", value: activeCount, urgent: activeCount > 0 },
    { label: "Terminés", value: completed },
    { label: "Échecs", value: failed, urgent: failed > 0 },
  ];

  const recent = jobs.slice(0, 8);

  return (
    <div className="max-w-4xl mx-auto">
      {/* Hero band */}
      <div
        className="rounded-xl px-6 py-8 mb-6"
        style={{ background: "var(--surface-deep)" }}
      >
        <h1
          className="text-2xl font-extrabold mb-2"
          style={{ color: "var(--text-on-dark)", fontFamily: "var(--font-manrope)" }}
        >
          Tableau de bord
        </h1>
        <p className="text-sm max-w-lg" style={{ color: "var(--text-on-dark-soft)" }}>
          Surveillez votre surface d'attaque externe. Ajoutez une cible dans le panneau de gauche
          pour lancer une analyse et découvrir les services exposés, vulnérabilités et failles de sécurité.
        </p>
      </div>

      {/* Stat tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {statTiles.map((t) => (
          <div key={t.label} className="panel card-pad">
            <p
              className="text-3xl font-extrabold tabular-nums tracking-tight"
              style={{
                color: t.urgent ? "var(--critical)" : "var(--text-primary)",
                fontFamily: "var(--font-manrope)",
              }}
            >
              {t.value}
            </p>
            <p className="text-[11px] font-semibold uppercase tracking-[0.06em] mt-1" style={{ color: "var(--text-secondary)" }}>
              {t.label}
            </p>
            {t.subtitle && (
              <p className="text-[11px] mt-1" style={{ color: "var(--text-secondary)" }}>
                {t.subtitle}
              </p>
            )}
          </div>
        ))}
      </div>

      {/* Recent activity */}
      <div className="panel">
        <div
          className="px-5 py-3 flex items-center justify-between"
          style={{ borderBottom: "1px solid var(--border)" }}
        >
          <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
            Activité récente
          </p>
          <span className="text-[11px] font-medium" style={{ color: "var(--text-secondary)" }}>
            {jobs.length} scan{jobs.length !== 1 ? "s" : ""} au total
          </span>
        </div>

        {recent.length === 0 ? (
          <p className="px-5 py-8 text-sm text-center" style={{ color: "var(--text-secondary)" }}>
            Aucune analyse pour le moment. Ajoutez une cible pour commencer.
          </p>
        ) : (
          <div className="divide-y" style={{ borderColor: "var(--border)" }}>
            {recent.map((j) => {
              const s = STATUS_PILL[j.status] || STATUS_PILL.pending;
              return (
                <button
                  key={j.id}
                  onClick={() => onSelectAsset(j.asset_id)}
                  className="w-full text-left px-5 py-3 flex items-center gap-3 transition-colors hover:bg-[var(--panel-dim)]"
                >
                  <span className="flex-1 min-w-0 flex items-center gap-2">
                    <span className="text-sm font-semibold truncate" style={{ color: "var(--text-primary)" }}>
                      {j.asset_value}
                    </span>
                    <span
                      className="text-xs shrink-0 font-medium"
                      style={{ color: "var(--text-secondary)" }}
                    >
                      {toolLabel(j.tool)}
                    </span>
                  </span>
                  <span className="text-[11px] shrink-0" style={{ color: "var(--text-secondary)" }}>
                    {j.completed_at ? timeAgo(j.completed_at) : "—"}
                  </span>
                  <span
                    className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full shrink-0"
                    style={{ color: s.color, background: s.bg, minWidth: 48, textAlign: "center" }}
                  >
                    {s.label}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
