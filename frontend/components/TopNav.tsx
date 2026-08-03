"use client";

type Props = {
  activeScanCount: number;
  selectedAssetValue: string | null;
  onTriggerScan?: () => void;
  scanning?: boolean;
};

export default function TopNav({
  activeScanCount,
  selectedAssetValue,
  onTriggerScan,
  scanning,
}: Props) {
  const live = activeScanCount > 0;

  return (
    <header
      className="sticky top-0 z-20 backdrop-blur shrink-0"
      style={{
        background: "color-mix(in srgb, var(--panel) 92%, transparent)",
        borderBottom: "1px solid var(--border)",
        height: "3.5rem",
      }}
    >
      <div className="h-full px-6 flex items-center justify-between">
        {/* Left: context breadcrumb */}
        <div className="flex items-center gap-3">
          {selectedAssetValue ? (
            <>
              <span
                className="text-xs font-semibold uppercase tracking-wider"
                style={{ color: "var(--text-secondary)" }}
              >
                Cible
              </span>
              <span className="mono text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                {selectedAssetValue}
              </span>
              {onTriggerScan && (
                <button
                  onClick={onTriggerScan}
                  disabled={scanning}
                  className="btn-primary"
                  style={{ padding: "5px 16px", fontSize: "13px" }}
                >
                  {scanning ? "Scan…" : "Scanner"}
                </button>
              )}
            </>
          ) : (
            <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
              Sélectionnez une cible pour commencer
            </span>
          )}
        </div>

        {/* Right: global status */}
        <div
          className="flex items-center gap-2 pl-3 pr-3.5 py-1.5 rounded-full"
          style={{
            background: live ? "var(--brand-dim)" : "var(--panel-dim)",
            border: `1px solid ${live ? "var(--brand-accent)" : "var(--border)"}`,
          }}
        >
          <span className={`status-dot ${live ? "status-dot--live" : "status-dot--idle"}`} />
          <span
            className="text-xs font-semibold"
            style={{ color: live ? "var(--brand-accent-hover)" : "var(--text-secondary)" }}
          >
            {live
              ? `${activeScanCount} scan${activeScanCount > 1 ? "s" : ""} actif${activeScanCount > 1 ? "s" : ""}`
              : "Inactif"}
          </span>
        </div>
      </div>
    </header>
  );
}
