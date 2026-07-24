"use client";

import { useState, useEffect, useMemo } from "react";
import AssetSearch from "../components/AssetSearch";
import ScanHistory from "../components/ScanHistory";
import FindingCard from "../components/FindingCard";
import StatsSummary from "../components/StatsSummary";
import FindingsToolbar from "../components/FindingsToolbar";
import { Asset, ScanJob, ScanResults, Severity } from "../types/scan";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE as string;
const ALL_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const ACTIVE_STATUSES = new Set(["pending", "running"]);

export default function Home() {
  const [asset, setAsset] = useState<Asset | null>(null);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [assetJobs, setAssetJobs] = useState<ScanJob[]>([]);

  const [search, setSearch] = useState("");
  const [activeSeverities, setActiveSeverities] = useState<Set<Severity>>(new Set(ALL_SEVERITIES));
  const [activeType, setActiveType] = useState<string | null>(null);

  const scanning = assetJobs.some((j) => ACTIVE_STATUSES.has(j.status));
  const runningTools = assetJobs
  .filter((j) => ACTIVE_STATUSES.has(j.status))
  .map((j) => j.tool);

  function selectAsset(a: Asset) {
    setAsset(a);
    setJob(null);
    setResults(null);
    setAssetJobs([]);
    resetFilters();
  }

  // Jump to a spawned asset (e.g. the IP a WHOIS job resolved and
  // queued Shodan for). Fetches the asset by id since it may not be
  // in AssetSearch's already-loaded list.
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
    <main className="max-w-3xl mx-auto mt-10 px-4 pb-20">
      <div className="flex items-center gap-2 mb-1">
        <span className="w-2 h-2 rounded-full" style={{ background: "var(--signal)" }} />
        <h1 className="mono text-sm uppercase tracking-[0.14em]" style={{ color: "var(--text)" }}>
          EASM ATTACK SURFACE SCANNER
        </h1>
      </div>
      <p className="text-sm mb-8" style={{ color: "var(--muted)" }}>
        Attack surface reconnaissance
      </p>

      <AssetSearch apiBase={API_BASE} onSelect={selectAsset} />

      {asset && (
        <>
         <div className={`panel flex items-center justify-between px-4 py-3 mb-4 ${scanning ? "scan-sweep" : ""}`}>
  <div>
    <div className="eyebrow">ACTIVE TARGET</div>
    <p className="mono text-base mt-0.5">{asset.value}</p>
    {runningTools.length > 0 && (
      <p className="mono text-xs mt-1" style={{ color: "var(--signal)" }}>
        running: {runningTools.join(", ")}
      </p>
    )}
  </div>
  <button onClick={triggerScan} disabled={scanning} className="btn-primary">
    {scanning ? "scanning…" : "run scan"}
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
        </>
      )}

      {!asset && (
        <p className="mono text-xs px-3 py-4" style={{ color: "var(--muted)", border: "1px dashed var(--hairline)" }}>
          // no target selected — search or add one above
        </p>
      )}

      {job && job.status === "failed" && (
        <p
          className="mono text-xs px-3 py-3 mb-4"
          style={{ color: "#E0525C", border: "1px solid #E0525C33", background: "#E0525C0d" }}
        >
          // scan failed — check job status or try again
        </p>
      )}

      {results?.findings && (
        <section>
          <StatsSummary findings={results.findings} />
          <FindingsToolbar
            search={search}
            onSearchChange={setSearch}
            activeSeverities={activeSeverities}
            onToggleSeverity={toggleSeverity}
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
              className="mono text-xs px-3 py-4 text-center"
              style={{ color: "var(--muted)", border: "1px dashed var(--hairline)" }}
            >
              // no findings match current filters
            </p>
          )}
        </section>
      )}
    </main>
  );
}
