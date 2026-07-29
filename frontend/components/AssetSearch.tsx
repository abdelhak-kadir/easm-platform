import { useMemo, useState } from "react";
import { Asset } from "../types/scan";

const TYPE_LABEL: Record<string, string> = {
  domain: "Domaine",
  subdomain: "Sous-domaine",
  ip: "IP",
};

export default function AssetSearch({
  assets,
  selectedAssetId,
  onSelect,
  onCreate,
}: {
  assets: Asset[];
  selectedAssetId?: number | null;
  onSelect: (asset: Asset) => void;
  onCreate: (value: string, assetType: string) => Promise<Asset>;
}) {
  const [query, setQuery] = useState("");
  const [newValue, setNewValue] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const filtered = useMemo(
    () => assets.filter((a) => a.value.toLowerCase().includes(query.toLowerCase())),
    [assets, query]
  );

  async function handleCreate() {
    const value = newValue.trim();
    if (!value) return;
    setCreating(true);
    setError(null);
    try {
      const asset = await onCreate(value, "ip");
      setNewValue("");
      onSelect(asset);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Une erreur inattendue s'est produite.");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="panel flex flex-col" style={{ maxHeight: "calc(100vh - 7rem)" }}>
      <div className="p-4" style={{ borderBottom: "1px solid var(--hairline)" }}>
        <p className="eyebrow mb-1">Que souhaitez-vous vérifier ?</p>
        <p className="text-xs mb-3" style={{ color: "var(--muted)" }}>
          Une adresse de site web ou une IP de serveur à analyser pour détecter des failles de sécurité.
        </p>
        <input
          className="field-input mb-3"
          placeholder="Rechercher…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="flex gap-2">
          <input
            className="field-input"
            placeholder="ex. example.com"
            value={newValue}
            onKeyDown={(e) => e.key === "Enter" && handleCreate()}
            onChange={(e) => setNewValue(e.target.value)}
          />
          <button
            onClick={handleCreate}
            disabled={!newValue.trim() || creating}
            className="btn-primary shrink-0"
          >
            {creating ? "…" : "Ajouter"}
          </button>
        </div>
        {error && (
          <p className="text-xs mt-2" style={{ color: "var(--danger)" }}>
            {error}
          </p>
        )}
      </div>

      <div className="overflow-y-auto flex-1">
        {filtered.length === 0 ? (
          <p className="px-4 py-6 text-sm text-center" style={{ color: "var(--muted)" }}>
            {assets.length === 0 ? "Aucune cible pour le moment." : "Aucune cible ne correspond à votre recherche."}
          </p>
        ) : (
          <ul>
            {filtered.map((a) => {
              const active = a.id === selectedAssetId;
              return (
                <li key={a.id}>
                  <button
                    onClick={() => onSelect(a)}
                    className="w-full text-left px-4 py-3 flex items-center justify-between gap-2 transition-colors"
                    style={{
                      background: active ? "var(--signal-dim)" : "transparent",
                      borderLeft: `3px solid ${active ? "var(--signal)" : "transparent"}`,
                    }}
                    onMouseEnter={(e) => {
                      if (!active) e.currentTarget.style.background = "var(--panel-alt)";
                    }}
                    onMouseLeave={(e) => {
                      if (!active) e.currentTarget.style.background = "transparent";
                    }}
                  >
                    <span className="mono text-sm truncate" style={{ color: "var(--text)" }}>
                      {a.value}
                    </span>
                    <span
                      className="text-[10px] font-semibold uppercase tracking-wide shrink-0 px-1.5 py-0.5 rounded"
                      style={{ color: "var(--muted)", background: "var(--panel-alt)" }}
                    >
                      {TYPE_LABEL[a.asset_type] || a.asset_type}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}
