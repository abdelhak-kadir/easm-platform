"use client";

import { useState, useCallback, useEffect } from "react";
import { Asset, AssetReputationResponse } from "../types/scan";

interface Props {
  apiBase: string;
  asset: Asset;
  refreshKey: number;
  onJumpToAsset: (id: number) => void;
}

/* Same color rule as AbuseipdbReportBody in FindingCard.tsx */
function scoreColor(score: number): string {
  return score >= 70 ? "var(--critical)" : score >= 30 ? "var(--high)" : "var(--text-primary)";
}

export default function DomainReputation({ apiBase, asset, refreshKey, onJumpToAsset }: Props) {
  const [data, setData] = useState<AssetReputationResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // On an IP page the block reads "Réputation IP" and shows the root
  // domain's aggregate (the endpoint groups by root_asset_id).
  const isIp = asset.asset_type === "ip";
  const title = isIp ? "Réputation IP" : "Réputation du domaine";

  const load = useCallback(() => {
    fetch(`${apiBase}/assets/${asset.id}/reputation`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((json: AssetReputationResponse) => {
        setData(json);
        setError(null);
      })
      .catch((e) => {
        setError(e.message);
      })
      .finally(() => setLoading(false));
  }, [apiBase, asset.id]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  if (loading && !data) {
    return (
      <div className="panel card-pad">
        <p className="eyebrow mb-2">{title}</p>
        <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
          Chargement de la réputation…
        </p>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="panel card-pad" style={{ borderColor: "var(--critical)", background: "var(--critical-dim)" }}>
        <p className="eyebrow mb-2">{title}</p>
        <p className="text-xs mb-3" style={{ color: "var(--critical)" }}>
          Erreur de chargement : {error}
        </p>
        <button
          onClick={() => {
            setLoading(true);
            load();
          }}
          className="btn-ghost text-xs"
        >
          Réessayer
        </button>
      </div>
    );
  }

  if (!data) return null;

  const { total_ips, listed_ips, total_zone_listings, ips, by_zone, unchecked_ips } = data;

  return (
    <div className="panel overflow-hidden">
      {/* ── Header ─────────────────────────────────────────────── */}
      <div
        className="px-4 py-3 flex items-center gap-2"
        style={{ background: "var(--panel-dim)", borderBottom: "1px solid var(--border)" }}
      >
        <span style={{ fontSize: "16px" }}>🛡</span>
        <span className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
          {title}
        </span>
        <span className="mono text-[10px]" style={{ color: "var(--text-secondary)" }}>
          {data.root_asset.value}
        </span>
      </div>

      {/* ── Counts ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-2 p-4">
        {[
          { label: "IPs vérifiées", value: total_ips, color: "var(--text-primary)" },
          { label: "IPs listées", value: listed_ips, color: listed_ips > 0 ? "var(--critical)" : "var(--success)" },
          { label: "Signalements RBL", value: total_zone_listings, color: total_zone_listings > 0 ? "var(--critical)" : "var(--success)" },
        ].map((k) => (
          <div key={k.label} className="card-pad text-center" style={{ background: "var(--panel-dim)" }}>
            <p className="text-xl font-extrabold tabular-nums" style={{ color: k.color, fontFamily: "var(--font-manrope)" }}>
              {k.value}
            </p>
            <p className="text-[10px] font-semibold uppercase tracking-[0.06em] mt-1" style={{ color: "var(--text-secondary)" }}>
              {k.label}
            </p>
          </div>
        ))}
      </div>

      {/* ── Per-IP rows ────────────────────────────────────────── */}
      {ips.length === 0 ? (
        <p className="px-4 pb-4 text-xs" style={{ color: "var(--text-secondary)" }}>
          Aucun résultat IP Blacklist pour cet actif.
        </p>
      ) : (
        <div className="divide-y" style={{ borderColor: "var(--border)" }}>
          {ips.map((e) => {
            const listed = e.listed_count > 0;
            return (
              <div key={e.asset_id} className="px-4 py-3">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <button
                    onClick={() => onJumpToAsset(e.asset_id)}
                    className="mono text-sm font-bold hover:underline"
                    style={{ color: "var(--text-primary)", cursor: "pointer" }}
                  >
                    {e.ip}
                  </button>
                  <div className="flex items-center gap-2 flex-wrap">
                    {e.tor_exit && (
                      <span
                        className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                        style={{ color: "var(--high)", background: "var(--high-dim)", border: "1px solid var(--high)" }}
                      >
                        Exit Tor
                      </span>
                    )}
                    {typeof e.abuseipdb_score === "number" && (
                      <span
                        className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                        style={{
                          color: scoreColor(e.abuseipdb_score),
                          background: "var(--panel-dim)",
                          border: `1px solid ${scoreColor(e.abuseipdb_score)}`,
                        }}
                      >
                        AbuseIPDB {e.abuseipdb_score}
                      </span>
                    )}
                    <span className="text-xs font-bold tabular-nums" style={{ color: listed ? "var(--critical)" : "var(--success)" }}>
                      {listed ? `${e.listed_count} liste${e.listed_count > 1 ? "s" : ""}` : "aucune liste"}
                    </span>
                  </div>
                </div>
                {e.zones.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {e.zones.map((z) => (
                      <span
                        key={`${e.ip}-${z.zone}`}
                        className="mono text-[10px] px-1.5 py-0.5 rounded"
                        style={{ color: "var(--critical)", background: "var(--critical-dim)", border: "1px solid var(--critical)" }}
                      >
                        {z.zone}
                        {z.code ? ` (${z.code})` : ""}
                      </span>
                    ))}
                  </div>
                )}
                {(e.zones_with_errors ?? 0) > 0 && (
                  <p className="text-[10px] mt-1" style={{ color: "var(--text-secondary)" }}>
                    {e.zones_with_errors} zone(s) non vérifiée(s) (erreur DNS)
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ── By RBL zone ────────────────────────────────────────── */}
      {by_zone.length > 0 && (
        <div className="px-4 py-3" style={{ borderTop: "1px solid var(--border)" }}>
          <p className="eyebrow mb-2">Par zone RBL</p>
          <div className="space-y-2">
            {by_zone.map((z) => (
              <div key={z.zone} className="flex items-center gap-2 flex-wrap">
                <span className="mono text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
                  {z.zone}
                </span>
                <span
                  className="text-[10px] tabular-nums font-bold px-1.5 py-0.5 rounded"
                  style={{ color: "var(--critical)", background: "var(--critical-dim)" }}
                >
                  {z.count}
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {z.listed_ips.map((ip) => (
                    <span
                      key={ip}
                      className="mono text-[10px] px-1.5 py-0.5 rounded"
                      style={{ color: "var(--text-secondary)", background: "var(--panel-dim)" }}
                    >
                      {ip}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Unchecked IPs ──────────────────────────────────────── */}
      {unchecked_ips.length > 0 && (
        <div className="px-4 py-3" style={{ borderTop: "1px solid var(--border)" }}>
          <p className="eyebrow mb-1">IPs non vérifiées</p>
          <p className="text-[10px] mb-2" style={{ color: "var(--text-secondary)" }}>
            Ces IPs n&apos;ont pas encore de scan IP Blacklist terminé.
          </p>
          <div className="flex flex-wrap gap-1.5">
            {unchecked_ips.map((ip) => (
              <span
                key={ip}
                className="mono text-[10px] px-1.5 py-0.5 rounded"
                style={{ color: "var(--high)", background: "var(--high-dim)", border: "1px solid var(--high)" }}
              >
                {ip}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
