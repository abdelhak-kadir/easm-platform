"use client";

import { Asset, DashboardToolSummary, RelatedAssetGroup, ScanJob } from "../types/scan";
import { toolLabel } from "../lib/labels";

/* ── Node layout constants ──────────────────────────────────────────── */
const SVG_W = 700;
const SVG_H = 280;
const ROOT_Y = 42;
const SCAN_Y = 130;
const SPAWN_Y = 220;
const ROOT_R = 24;
const SCAN_R = 18;
const SPAWN_R = 14;
const LEGEND_Y = 258;

/* ── Status → stroke colour ─────────────────────────────────────────── */
function statusStroke(status: string | null): string {
  switch (status) {
    case "completed":
      return "var(--success)";
    case "running":
      return "var(--high)";
    case "pending":
      return "var(--text-secondary)";
    case "failed":
      return "var(--critical)";
    default:
      return "var(--border)";
  }
}

function statusFill(status: string | null): string {
  // dim version of the stroke
  switch (status) {
    case "completed":
      return "var(--success-dim)";
    case "running":
      return "var(--high-dim)";
    case "pending":
      return "var(--panel-dim)";
    case "failed":
      return "var(--critical-dim)";
    default:
      return "var(--panel-dim)";
  }
}

/* ── Tool → emoji icon ──────────────────────────────────────────────── */
function toolEmoji(tool: string): string {
  const m: Record<string, string> = {
    whois: "🔍",
    shodan: "🖥",
    censys: "🌐",
    reverse_dns: "🔄",
    email_security: "📧",
    theharvester: "🌾",
    subfinder: "🔎",
    amass: "📡",
    merklemap: "🗺",
    httpx: "🌍",
    nmap: "🔌",
    holehe: "📋",
    ssl_checker: "🔒",
    certspotter: "📜",
  };
  return m[tool] || "⚙";
}

function assetEmoji(assetType: string): string {
  const m: Record<string, string> = {
    domain: "🌐",
    subdomain: "🔗",
    ip: "🖥",
    email: "📧",
    service: "⚡",
    technology: "📊",
  };
  return m[assetType] || "•";
}

/* ── Types ───────────────────────────────────────────────────────────── */

interface Props {
  asset: Asset;
  toolSummary: DashboardToolSummary[];
  relatedAssets: RelatedAssetGroup[];
  onSelectJob: (job: ScanJob) => void;
  onJumpToAsset: (assetId: number) => void;
}

/* ── Component ──────────────────────────────────────────────────────── */

export default function TopologyMap({
  asset,
  toolSummary,
  relatedAssets,
  onSelectJob,
  onJumpToAsset,
}: Props) {
  // ── Build graph data ──────────────────────────────────────────────
  // Scan nodes: every tool that has been run
  const scanNodes = toolSummary
    .filter((ts) => ts.latest_job !== null || ts.applicable)
    .map((ts) => ({
      tool: ts.tool,
      label: toolLabel(ts.tool).split(" (")[0], // short label
      status: ts.latest_status,
      job: ts.latest_job,
      emoji: toolEmoji(ts.tool),
    }));

  // Spawned asset nodes: related assets that are children
  const spawnedNodes = relatedAssets
    .filter((ra) => ra.relation === "child" || ra.relation === "both")
    .map((ra) => ({
      assetId: ra.asset.id,
      value: ra.asset.value,
      type: ra.asset.asset_type,
      emoji: assetEmoji(ra.asset.asset_type),
      status: ra.summary.latest_status,
      // Which tool spawned this? Look at links
      parentTool: ra.links.length > 0 ? ra.links[0].tool : null,
      parentJobId: ra.links.length > 0 ? ra.links[0].id : null,
    }));

  // If nothing to show
  if (scanNodes.length === 0 && spawnedNodes.length === 0) {
    return (
      <div className="panel card-pad mb-5">
        <p className="eyebrow mb-3">Topologie de découverte</p>
        <p className="text-xs text-center py-6" style={{ color: "var(--text-secondary)" }}>
          Lancez une analyse pour voir la chaîne de découverte.
        </p>
      </div>
    );
  }

  // ── Layout calculations ────────────────────────────────────────────
  // Scan row: distribute across full width
  const scanCount = scanNodes.length;
  const scanSpacing = scanCount > 1 ? Math.min(120, (SVG_W - 80) / (scanCount - 1)) : 0;
  const scanTotalW = (scanCount - 1) * scanSpacing;

  function scanX(i: number): number {
    if (scanCount === 1) return SVG_W / 2;
    return SVG_W / 2 - scanTotalW / 2 + i * scanSpacing;
  }

  // Spawn row: distribute across full width
  const spawnCount = spawnedNodes.length;
  const spawnSpacing = spawnCount > 1 ? Math.min(130, (SVG_W - 60) / (spawnCount - 1)) : 0;
  const spawnTotalW = (spawnCount - 1) * spawnSpacing;

  function spawnX(i: number): number {
    if (spawnCount === 1) return SVG_W / 2;
    return SVG_W / 2 - spawnTotalW / 2 + i * spawnSpacing;
  }

  // Build a quick lookup: spawned asset -> parent tool name
  const spawnToParentTool = new Map<number, string>();
  for (const sn of spawnedNodes) {
    if (sn.parentTool) spawnToParentTool.set(sn.assetId, sn.parentTool);
  }

  // Scan tool name -> scan index (for drawing edges)
  const toolToScanIdx = new Map<string, number>();
  scanNodes.forEach((sn, i) => toolToScanIdx.set(sn.tool, i));

  return (
    <div className="panel mb-5 overflow-hidden">
      <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--border)" }}>
        <p className="eyebrow" style={{ marginBottom: 0 }}>
          Topologie de découverte
        </p>
        <span className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
          {scanNodes.length} outil{scanNodes.length !== 1 ? "s" : ""} · {spawnedNodes.length} actif{spawnedNodes.length !== 1 ? "s" : ""} découvert{spawnedNodes.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div className="p-4 flex justify-center" style={{ background: "var(--panel-dim)" }}>
        <svg
          viewBox={`0 0 ${SVG_W} ${SVG_H}`}
          className="topology-svg"
          style={{ width: "100%", maxWidth: SVG_W, height: "auto" }}
        >
          {/* ── Edges: root → scans ──────────────────────────────── */}
          {scanNodes.map((sn, i) => (
            <line
              key={`edge-root-${sn.tool}`}
              x1={SVG_W / 2}
              y1={ROOT_Y + ROOT_R}
              x2={scanX(i)}
              y2={SCAN_Y - SCAN_R}
              className="topo-edge"
              strokeDasharray={sn.status === "completed" ? undefined : "4,3"}
            />
          ))}

          {/* ── Edges: scans → spawned assets ────────────────────── */}
          {spawnedNodes.map((sn, si) => {
            if (!sn.parentTool) return null;
            const scanIdx = toolToScanIdx.get(sn.parentTool);
            if (scanIdx === undefined) return null;
            return (
              <line
                key={`edge-spawn-${sn.assetId}`}
                x1={scanX(scanIdx)}
                y1={SCAN_Y + SCAN_R}
                x2={spawnX(si)}
                y2={SPAWN_Y - SPAWN_R}
                className="topo-edge"
                strokeDasharray="4,3"
              />
            );
          })}

          {/* ── Root node ────────────────────────────────────────── */}
          <g className="topo-node" style={{ cursor: "default" }}>
            <circle
              cx={SVG_W / 2}
              cy={ROOT_Y}
              r={ROOT_R}
              fill="var(--panel)"
              stroke="var(--brand-accent)"
              strokeWidth="2.5"
            />
            <text
              x={SVG_W / 2}
              y={ROOT_Y + 5}
              textAnchor="middle"
              fill="var(--text-primary)"
              fontSize="13"
              fontWeight="700"
              fontFamily="var(--font-inter)"
            >
              {assetEmoji(asset.asset_type)}
            </text>
          </g>
          <text
            x={SVG_W / 2}
            y={ROOT_Y + ROOT_R + 16}
            textAnchor="middle"
            fill="var(--text-primary)"
            fontSize="11"
            fontWeight="600"
            fontFamily="var(--font-manrope)"
          >
            {asset.value.length > 22 ? asset.value.slice(0, 22) + "…" : asset.value}
          </text>

          {/* ── Scan nodes ───────────────────────────────────────── */}
          {scanNodes.map((sn, i) => {
            const stroke = statusStroke(sn.status);
            const fill = statusFill(sn.status);
            return (
              <g
                key={`scan-${sn.tool}`}
                className="topo-node topo-node--clickable"
                style={{ cursor: sn.job ? "pointer" : "default" }}
                onClick={() => {
                  if (sn.job) onSelectJob(sn.job);
                }}
              >
                <circle
                  cx={scanX(i)}
                  cy={SCAN_Y}
                  r={SCAN_R}
                  fill={fill}
                  stroke={stroke}
                  strokeWidth="2"
                />
                <text
                  x={scanX(i)}
                  y={SCAN_Y + 5}
                  textAnchor="middle"
                  fill="var(--text-primary)"
                  fontSize="11"
                  fontWeight="600"
                  fontFamily="var(--font-inter)"
                >
                  {sn.emoji}
                </text>
                <text
                  x={scanX(i)}
                  y={SCAN_Y + SCAN_R + 14}
                  textAnchor="middle"
                  fill="var(--text-secondary)"
                  fontSize="9"
                  fontWeight="500"
                  fontFamily="var(--font-inter)"
                >
                  {sn.label.length > 14 ? sn.label.slice(0, 14) + "…" : sn.label}
                </text>
              </g>
            );
          })}

          {/* ── Spawned asset nodes ───────────────────────────────── */}
          {spawnedNodes.map((sn, si) => {
            const stroke = statusStroke(sn.status);
            const fill = statusFill(sn.status);
            return (
              <g
                key={`spawn-${sn.assetId}`}
                className="topo-node topo-node--clickable"
                style={{ cursor: "pointer" }}
                onClick={() => onJumpToAsset(sn.assetId)}
              >
                <circle
                  cx={spawnX(si)}
                  cy={SPAWN_Y}
                  r={SPAWN_R}
                  fill={fill}
                  stroke={stroke}
                  strokeWidth="1.5"
                />
                <text
                  x={spawnX(si)}
                  y={SPAWN_Y + 4}
                  textAnchor="middle"
                  fill="var(--text-secondary)"
                  fontSize="9"
                  fontWeight="600"
                  fontFamily="var(--font-inter)"
                >
                  {sn.emoji}
                </text>
                <text
                  x={spawnX(si)}
                  y={SPAWN_Y + SPAWN_R + 12}
                  textAnchor="middle"
                  fill="var(--text-secondary)"
                  fontSize="8"
                  fontWeight="500"
                  fontFamily="var(--font-inter)"
                >
                  {sn.value.length > 14 ? sn.value.slice(0, 14) + "…" : sn.value}
                </text>
              </g>
            );
          })}

          {/* ── Legend ────────────────────────────────────────────── */}
          <g>
            <rect x="8" y={LEGEND_Y} width="6" height="6" rx="1" fill="var(--critical)" />
            <text x="18" y={LEGEND_Y + 5.5} fill="var(--text-secondary)" fontSize="8" fontFamily="var(--font-inter)">
              Échec
            </text>
            <rect x="48" y={LEGEND_Y} width="6" height="6" rx="1" fill="var(--success)" />
            <text x="58" y={LEGEND_Y + 5.5} fill="var(--text-secondary)" fontSize="8" fontFamily="var(--font-inter)">
              Terminé
            </text>
            <rect x="105" y={LEGEND_Y} width="6" height="6" rx="1" fill="var(--high)" />
            <text x="115" y={LEGEND_Y + 5.5} fill="var(--text-secondary)" fontSize="8" fontFamily="var(--font-inter)">
              En cours
            </text>
            <rect x="165" y={LEGEND_Y} width="6" height="6" rx="1" fill="var(--text-secondary)" />
            <text x="175" y={LEGEND_Y + 5.5} fill="var(--text-secondary)" fontSize="8" fontFamily="var(--font-inter)">
              En attente
            </text>
          </g>
        </svg>
      </div>
    </div>
  );
}
