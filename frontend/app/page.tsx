"use client";

import { useState, useEffect } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE;

const SEVERITY_COLORS = {
  info: "border-gray-400",
  low: "border-blue-400",
  medium: "border-yellow-400",
  high: "border-orange-400",
  critical: "border-red-500",
};

export default function Home() {
  const [assetValue, setAssetValue] = useState("");
  const [assetId, setAssetId] = useState(null);
  const [job, setJob] = useState(null);
  const [results, setResults] = useState(null);

  async function createAsset() {
    const res = await fetch(`${API_BASE}/assets`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value: assetValue, asset_type: "ip" }),
    });
    const data = await res.json();
    setAssetId(data.id);
    setResults(null);
    setJob(null);
  }

  async function triggerScan() {
    const res = await fetch(`${API_BASE}/scans/shodan/${assetId}`, { method: "POST" });
    const data = await res.json();
    setJob({ id: data.job_id, status: "queued" });
  }

  useEffect(() => {
  if (!job || ["completed", "failed"].includes(job.status)) return;
  const interval = setInterval(async () => {
    const res = await fetch(`${API_BASE}/scans/${job.id}`);
    const data = await res.json();
    setJob(data);
    if (data.status === "completed") {
      const resultsRes = await fetch(`${API_BASE}/scans/${job.id}/results`);
      if (!resultsRes.ok) {
        console.error("Results fetch failed:", resultsRes.status, await resultsRes.text());
        return;
      }
      setResults(await resultsRes.json());
    }
  }, 2000);
  return () => clearInterval(interval);
}, [job]);

  return (
    <main className="max-w-2xl mx-auto mt-10 px-4 font-sans">
      <h1 className="text-2xl font-bold mb-6">EASM — Shodan Scan MVP</h1>

      <section className="mb-6 flex gap-2">
        <input
          className="border rounded px-3 py-1 flex-1"
          placeholder="IP or domain (e.g. 8.8.8.8)"
          value={assetValue}
          onChange={(e) => setAssetValue(e.target.value)}
        />
        <button
          className="bg-black text-white px-4 py-1 rounded disabled:opacity-40"
          onClick={createAsset}
          disabled={!assetValue}
        >
          Add asset
        </button>
      </section>
      {assetId && <p className="text-sm text-gray-500 mb-4">Asset #{assetId} created</p>}

      {assetId && (
        <section className="mb-6">
          <button className="bg-blue-600 text-white px-4 py-1 rounded" onClick={triggerScan}>
            Run Shodan scan
          </button>
          {job && (
            <p className="text-sm mt-2">
              Job #{job.id} — status: <strong>{job.status}</strong>
            </p>
          )}
        </section>
      )}

      {results?.findings && (
        <section>
          <h2 className="text-lg font-semibold mb-3">
            Findings ({results.findings.length})
          </h2>
          {results.findings.map((f) => (
            <div
              key={f.id}
              className={`border-l-4 ${SEVERITY_COLORS[f.severity] || "border-gray-300"} bg-gray-50 rounded p-3 mb-2`}
            >
              <div className="flex items-center gap-2">
                <strong>{f.title}</strong>
                <span className="text-xs text-gray-500">
                  {f.finding_type} · {f.severity}
                </span>
              </div>
              <pre className="text-xs whitespace-pre-wrap mt-1 text-gray-700">
                {JSON.stringify(f.data, null, 2)}
              </pre>
            </div>
          ))}
        </section>
      )}
    </main>
  );
}
