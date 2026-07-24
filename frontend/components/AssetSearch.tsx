import { useState, useEffect, useMemo } from "react";
import { Asset } from "../types/scan";

// Very small heuristic: valid IPv4 dotted-quad, or IPv6 containing a colon.
// Anything else (has a dot but isn't numeric, or no dot at all but looks
// hostname-like) is treated as a domain. This only needs to disambiguate
// what the backend's tool registry cares about (AssetType.IP vs DOMAIN),
// so it doesn't need to be a full RFC-grade validator.
function inferAssetType(value: string): "ip" | "domain" {
  const v = value.trim();
  const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (IPV4_RE.test(v)) {
    const octets = v.split(".").map(Number);
    if (octets.every((o) => o >= 0 && o <= 255)) return "ip";
  }
  if (v.includes(":")) return "ip"; // crude IPv6 check
  return "domain";
}

export default function AssetSearch({
  apiBase,
  onSelect,
}: {
  apiBase: string;
  onSelect: (asset: Asset) => void;
}) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [query, setQuery] = useState("");
  const [newValue, setNewValue] = useState("");
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    fetch(`${apiBase}/assets`)
      .then((r) => r.json())
      .then(setAssets)
      .catch(() => setAssets([]));
  }, [apiBase]);

  const filtered = useMemo(
    () => assets.filter((a) => a.value.toLowerCase().includes(query.toLowerCase())),
    [assets, query]
  );

  async function handleCreate() {
    if (!newValue.trim()) return;
    setCreating(true);
    try {
      const value = newValue.trim();
      const res = await fetch(`${apiBase}/assets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value, asset_type: inferAssetType(value) }),
      });
      const data: Asset = await res.json();
      setAssets((prev) => (prev.some((a) => a.id === data.id) ? prev : [...prev, data]));
      setNewValue("");
      onSelect(data);
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="mb-6">
      <div className="eyebrow mb-1.5">TARGET</div>
      <input
        className="field-input mb-2"
        placeholder="search existing targets…"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />

      {query && (
        <div className="panel mb-3 overflow-hidden divide-y" style={{ borderColor: "var(--hairline)" }}>
          {filtered.length > 0 ? (
            filtered.map((a) => (
              <button
                key={a.id}
                onClick={() => {
                  onSelect(a);
                  setQuery("");
                }}
                className="mono w-full text-left px-3 py-2 text-sm transition-colors"
                style={{ borderColor: "var(--hairline)" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--panel-alt)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                {a.value} <span style={{ color: "var(--muted)" }}>[{a.asset_type}]</span>
              </button>
            ))
          ) : (
            <p className="px-3 py-2 text-sm" style={{ color: "var(--muted)" }}>
              no matching targets
            </p>
          )}
        </div>
      )}

      <div className="eyebrow mb-1.5">NEW TARGET</div>
      <div className="flex gap-2">
        <input
          className="field-input"
          placeholder="ip or domain"
          value={newValue}
          onKeyDown={(e) => e.key === "Enter" && handleCreate()}
          onChange={(e) => setNewValue(e.target.value)}
        />
        <button
          onClick={handleCreate}
          disabled={!newValue.trim() || creating}
          className="btn-primary shrink-0"
        >
          {creating ? "adding…" : "add"}
        </button>
      </div>
    </div>
  );
}
