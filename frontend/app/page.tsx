"use client";

import { useState, useEffect, useMemo, useRef } from "react";
import TopNav from "../components/TopNav";
import Sidebar from "../components/Sidebar";
import AssetDashboard from "../components/AssetDashboard";
import ScanDetailPanel from "../components/ScanDetailPanel";
import FleetDashboard from "../components/FleetDashboard";
import SuggestAssetsPanel from "../components/SuggestAssetsPanel";
import SuggestHostsPanel from "../components/SuggestHostsPanel";
import { useAssets } from "../lib/useAssets";
import { useFleetScans } from "../lib/useFleetScans";
import { Asset, ScanJob, ScanResults, Severity } from "../types/scan";
import DiscoveryProgress from "../components/DiscoveryProgress";
import { ToastContainer, showToast } from "../components/Toast";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE as string;
const ALL_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const ACTIVE_STATUSES = new Set(["pending", "running"]);

export default function Home() {
  const { assets, createAsset, refresh: refreshAssets } = useAssets(API_BASE);
  const { jobs: fleetJobs, activeJobs: fleetActiveJobs, refresh: refreshFleet } = useFleetScans(API_BASE);

  const [asset, setAsset] = useState<Asset | null>(null);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [assetJobs, setAssetJobs] = useState<ScanJob[]>([]);

  const [search, setSearch] = useState("");
  const [activeSeverities, setActiveSeverities] = useState<Set<Severity>>(new Set(ALL_SEVERITIES));
  const [activeType, setActiveType] = useState<string | null>(null);

  const [discovering, setDiscovering] = useState(false);
  const findingsRef = useRef<HTMLDivElement>(null);

  const scanning = assetJobs.some((j) => ACTIVE_STATUSES.has(j.status));
  const busy = scanning || discovering;
  const activeScanCount = fleetActiveJobs.length;

  function selectAsset(a: Asset | null) {
    setAsset(a);
    setJob(null);
    setResults(null);
    setAssetJobs([]);
    resetFilters();
  }

  function selectAssetById(assetId: number) {
    const found = assets.find((a) => a.id === assetId);
    if (found) selectAsset(found);
  }

  async function jumpToAsset(assetId: number) {
    const res = await fetch(`${API_BASE}/assets/${assetId}`);
    if (!res.ok) return;
    const data: Asset = await res.json();
    selectAsset(data);
  }

  function resetFilters() {
    setSearch("");
    setActiveSeverities(new Set(ALL_SEVERITIES));
    setActiveType(null);
  }

  function toggleSeverity(s: Severity) {
    setActiveSeverities((prev) => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });
  }

  async function triggerScan() {
    if (!asset) return;
    try {
      const res = await fetch(`${API_BASE}/scans/discover/${asset.id}`, { method: "POST" });
      if (!res.ok) {
        showToast("Échec du lancement de l'analyse", "error");
        return;
      }
      showToast("Analyse lancée", "success");
    } catch {
      showToast("Impossible de contacter le serveur", "error");
    }
    setJob(null);
    setResults(null);
    resetFilters();
    setHistoryRefresh((k) => k + 1);
    refreshFleet();
  }

  async function triggerDiscovery() {
    if (!asset) return;
    setDiscovering(true);
    try {
      const res = await fetch(`${API_BASE}/scans/discovery/start/${asset.id}`, {
        method: "POST",
      });
      if (!res.ok) {
        let detail = "";
        try {
          detail = (await res.json()).detail || "";
        } catch {
          // keep empty
        }
        throw new Error(detail || `Erreur ${res.status}`);
      }
      const data = await res.json();
      setAsset((prev) => (prev ? { ...prev, discovery_run_id: data.run_id } : null));
      refreshAssets();
      setHistoryRefresh((k) => k + 1);
      refreshFleet();
    } catch (err: any) {
      showToast(err.message || "Échec du lancement de la découverte", "error");
    } finally {
      setDiscovering(false);
    }
  }

  async function loadResults(jobId: number) {
    const res = await fetch(`${API_BASE}/scans/${jobId}/results`);
    if (!res.ok) return;
    setResults(await res.json());
  }

  function selectPastJob(j: ScanJob) {
    setJob(j);
    resetFilters();
    if (j.status === "completed") {
      loadResults(j.id).then(() => {
        // Auto-scroll to findings after results load
        setTimeout(() => {
          findingsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
        }, 150);
      });
    } else {
      setResults(null);
    }
  }

  useEffect(() => {
    if (!asset || !busy) return;
    const interval = setInterval(() => {
      setHistoryRefresh((k) => k + 1);
    }, 2000);
    return () => clearInterval(interval);
  }, [asset, busy]);

  useEffect(() => {
    if (!job) return;
    const latest = assetJobs.find((j) => j.id === job.id);
    if (latest && latest.status !== job.status) {
      setJob(latest);
      if (latest.status === "completed") loadResults(latest.id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [assetJobs]);

  const typeOptions = useMemo(
    () => [...new Set((results?.findings || []).map((f) => f.finding_type))],
    [results]
  );

  const filteredFindings = useMemo(() => {
    if (!results?.findings) return [];
    return results.findings.filter((f) => {
      if (!activeSeverities.has(f.severity)) return false;
      if (activeType && f.finding_type !== activeType) return false;
      if (search) {
        const haystack = `${f.title} ${JSON.stringify(f.data)}`.toLowerCase();
        if (!haystack.includes(search.toLowerCase())) return false;
      }
      return true;
    });
  }, [results, activeSeverities, activeType, search]);

  return (
    <div className="min-h-screen flex flex-col" style={{ background: "var(--canvas)" }}>
      <ToastContainer />
      <TopNav
        activeScanCount={activeScanCount}
        selectedAssetValue={asset?.value ?? null}
        onTriggerScan={asset ? triggerScan : undefined}
        scanning={busy}
        onBackToDashboard={asset ? () => selectAsset(null) : undefined}
      />

      <div className="flex flex-1" style={{ height: "calc(100vh - 3.5rem)" }}>
        {/* Sidebar */}
        <div className="w-[264px] shrink-0 h-full">
          <Sidebar
            assets={assets}
            selectedAssetId={asset?.id}
            activeScanCount={activeScanCount}
            fleetJobs={fleetJobs}
            onSelect={selectAsset}
            onCreate={createAsset}
          />
        </div>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto px-6 py-6">
          {!asset ? (
            <FleetDashboard
              apiBase={API_BASE}
              assets={assets}
              jobs={fleetJobs}
              activeCount={activeScanCount}
              onSelectAsset={selectAssetById}
              onRefresh={refreshFleet}
            />
          ) : (
            /* ── Asset selected ── */
            <div className="max-w-4xl mx-auto">
              {/* Back navigation */}
              <button
                onClick={() => selectAsset(null)}
                className="flex items-center gap-1.5 text-xs font-semibold mb-4 px-3 py-1.5 rounded-full transition-all hover:opacity-80"
                style={{
                  color: "var(--brand-accent)",
                  background: "var(--brand-dim)",
                  border: "1px solid var(--brand-accent)",
                }}
              >
                <span>←</span> Tableau de bord
              </button>

              {/* Asset header + scan / discovery buttons */}
              <div
                className="panel flex items-center justify-between px-5 py-4 mb-5"
                style={busy ? { position: "relative", overflow: "hidden" } : undefined}
              >
                {busy && <div className="scan-sweep" style={{ position: "absolute", inset: 0 }} />}
                <div className="relative z-10">
                  <p className="eyebrow mb-1">Cible sélectionnée</p>
                  <p className="mono text-base font-semibold" style={{ color: "var(--text-primary)" }}>
                    {asset.value}
                  </p>
                  <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
                    {busy
                      ? "Analyse en cours — les résultats apparaîtront automatiquement."
                      : "Analyse rapide sur cet asset, ou découverte par vagues pour explorer récursivement."}
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0 relative z-10">
                  <button
                    onClick={triggerScan}
                    disabled={busy}
                    className="btn-primary text-sm"
                  >
                    {scanning ? "Analyse en cours…" : "Analyse rapide"}
                  </button>
                  <button
                    onClick={triggerDiscovery}
                    disabled={busy}
                    className="btn-primary text-sm"
                    style={{
                      background: "var(--brand-dim)",
                      borderColor: "var(--brand-accent)",
                      color: "var(--brand-accent)",
                    }}
                  >
                    {discovering ? "…" : "Découverte"}
                  </button>
                </div>
              </div>

              {/* Discovery progress (wave orchestrator) */}
              {asset.discovery_run_id != null && (
                <DiscoveryProgress
                  apiBase={API_BASE}
                  runId={asset.discovery_run_id}
                  onRefreshAssets={refreshAssets}
                />
              )}

              {/* Asset dashboard (tool cards + risk + related assets) */}
              <AssetDashboard
                apiBase={API_BASE}
                asset={asset}
                refreshKey={historyRefresh}
                onSelectJob={selectPastJob}
                onJumpToAsset={jumpToAsset}
                onJobsLoaded={setAssetJobs}
              />

              {/* ── Scan detail panel (when a job is selected) ──────── */}
              {job && (
                <div ref={findingsRef}>
                  <ScanDetailPanel
                    job={job}
                    results={results}
                    assetValue={asset.value}
                    apiBase={API_BASE}
                  />
                </div>
              )}

              {/* Suggestion panels */}
              {job && job.tool === "shodan" && job.status === "completed" && (
                <SuggestAssetsPanel
                  apiBase={API_BASE}
                  jobId={job.id}
                  onAssetsAccepted={() => {
                    refreshAssets();
                    setHistoryRefresh((k) => k + 1);
                  }}
                />
              )}

              {job && ["theharvester", "subfinder", "amass", "merklemap", "certspotter"].includes(job.tool) && job.status === "completed" && (
                <SuggestHostsPanel
                  apiBase={API_BASE}
                  jobId={job.id}
                  discoveryRunId={asset.discovery_run_id}
                  onAssetsAccepted={() => {
                    refreshAssets();
                    setHistoryRefresh((k) => k + 1);
                  }}
                />
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
