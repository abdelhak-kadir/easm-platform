"use client";

import { useState, useEffect, useMemo } from "react";
import TopNav from "../components/TopNav";
import OverviewStrip from "../components/OverviewStrip";
import AssetSearch from "../components/AssetSearch";
import ScanHistory from "../components/ScanHistory";
import FindingCard from "../components/FindingCard";
import StatsSummary from "../components/StatsSummary";
import SeverityChart from "../components/SeverityChart";
import RiskSummary from "../components/RiskSummary";
import FindingsToolbar from "../components/FindingsToolbar";
import SuggestAssetsPanel from "../components/SuggestAssetsPanel";
import { useAssets } from "../lib/useAssets";
import { useFleetScans } from "../lib/useFleetScans";
import { Asset, ScanJob, ScanResults, Severity } from "../types/scan";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE as string;
const ALL_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const ACTIVE_STATUSES = new Set(["pending", "running"]);

export default function Home() {
  const { assets, createAsset, refresh: refreshAssets } = useAssets(API_BASE);
  const { jobs: fleetJobs, activeJobs: fleetActiveJobs, refresh: refreshFleet } = useFleetScans(API_BASE, assets);

  const [asset, setAsset] = useState<Asset | null>(null);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [assetJobs, setAssetJobs] = useState<ScanJob[]>([]);

  const [search, setSearch] = useState("");
  const [activeSeverities, setActiveSeverities] = useState<Set<Severity>>(new Set(ALL_SEVERITIES));
  const [activeType, setActiveType] = useState<string | null>(null);

  const scanning = assetJobs.some((j) => ACTIVE_STATUSES.has(j.status));

  function selectAsset(a: Asset) {
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

  // Jump to a spawned asset (e.g. the IP a WHOIS job resolved and
  // queued Shodan for). Fetches the asset by id since it may not be
  // in the loaded list yet.
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
    await fetch(`${API_BASE}/scans/discover/${asset.id}`, { method: "POST" });
    setJob(null);
    setResults(null);
    resetFilters();
    setHistoryRefresh((k) => k + 1);
    refreshFleet();
  }

  async function loadResults(jobId: number) {
    const res = await fetch(`${API_BASE}/scans/${jobId}/results`);
    if (!res.ok) return;
    setResults(await res.json());
  }

  function selectPastJob(j: ScanJob) {
    setJob(j);
    resetFilters();
    if (j.status === "completed") loadResults(j.id);
    else setResults(null);
  }

  useEffect(() => {
    if (!asset || !scanning) return;
    const interval = setInterval(() => {
      setHistoryRefresh((k) => k + 1);
    }, 2000);
    return () => clearInterval(interval);
  }, [asset, scanning]);

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
    <div className="min-h-screen">
      <TopNav activeScanCount={fleetActiveJobs.length} />

      <main className="max-w-6xl mx-auto px-6 py-8">
        <OverviewStrip
          assets={assets}
          jobs={fleetJobs}
          activeCount={fleetActiveJobs.length}
          onSelectAsset={selectAssetById}
        />

        <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-6 items-start">
          <AssetSearch
            assets={assets}
            selectedAssetId={asset?.id}
            onSelect={selectAsset}
            onCreate={createAsset}
          />

          <section>
            {!asset && (
              <div
                className="panel px-6 py-16 text-center"
                style={{ color: "var(--muted)" }}
              >
                <p className="text-sm font-medium mb-1" style={{ color: "var(--text)" }}>
                  Choisissez une cible à vérifier
                </p>
                <p className="text-sm max-w-sm mx-auto">
                  Sélectionnez une cible dans la liste à gauche, ou ajoutez une adresse de site
                  web ou une IP que vous souhaitez vérifier.
                </p>
              </div>
            )}

            {asset && (
              <>
                <div className={`panel flex items-center justify-between px-5 py-4 mb-5 ${scanning ? "scan-sweep" : ""}`}>
                  <div>
                    <p className="eyebrow mb-1">Cible en cours de vérification</p>
                    <p className="mono text-base font-medium">{asset.value}</p>
                    <p className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>
                      {scanning
                        ? "Vérification de sécurité en cours — cela prend généralement une à deux minutes."
                        : "Lancez une vérification pour détecter d'éventuelles failles de sécurité sur cette cible."}
                    </p>
                  </div>
                  <button onClick={triggerScan} disabled={scanning} className="btn-primary shrink-0">
                    {scanning ? "Vérification…" : "Vérifier maintenant"}
                  </button>
                </div>

                <ScanHistory
                  apiBase={API_BASE}
                  asset={asset}
                  onSelectJob={selectPastJob}
                  refreshKey={historyRefresh}
                  activeJobId={job?.id}
                  onJobsLoaded={setAssetJobs}
                  onJumpToAsset={jumpToAsset}
                />

                {job && job.status === "failed" && (
                  <p
                    className="text-sm px-4 py-3 mb-5 rounded-lg"
                    style={{ color: "var(--danger)", border: "1px solid var(--danger)", background: "var(--danger-dim)" }}
                  >
                    La vérification a échoué — consultez le statut ci-dessus ou réessayez.
                  </p>
                )}

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

                {results?.findings && (
                  <section>
                    <RiskSummary findings={results.findings} assetValue={asset.value} />
                    <StatsSummary findings={results.findings} />
                    {results.findings.length > 0 && <SeverityChart findings={results.findings} />}
                    <FindingsToolbar
                      search={search}
                      onSearchChange={setSearch}
                      activeSeverities={activeSeverities}
                      onToggleSeverity={toggleSeverity}
                      onSetSeverities={setActiveSeverities}
                      typeOptions={typeOptions}
                      activeType={activeType}
                      onTypeChange={setActiveType}
                      resultCount={filteredFindings.length}
                      totalCount={results.findings.length}
                    />

                    {filteredFindings.length > 0 ? (
                      filteredFindings.map((f) => <FindingCard key={f.id} finding={f} />)
                    ) : (
                      <p
                        className="text-sm px-4 py-6 text-center rounded-lg"
                        style={{ color: "var(--muted)", border: "1px dashed var(--hairline)" }}
                      >
                        Aucun résultat ne correspond aux filtres actuels.
                      </p>
                    )}
                  </section>
                )}
              </>

            )}
          </section>
        </div>
      </main>
    </div>
  );
}
