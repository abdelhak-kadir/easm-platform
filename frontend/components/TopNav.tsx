export default function TopNav({ activeScanCount }: { activeScanCount: number }) {
  const live = activeScanCount > 0;

  return (
    <header
      className="sticky top-0 z-20 backdrop-blur"
      style={{
        background: "color-mix(in srgb, var(--ink) 88%, transparent)",
        borderBottom: "1px solid var(--hairline)",
      }}
    >
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div
            className="w-7 h-7 rounded-md flex items-center justify-center text-white text-xs font-bold shrink-0"
            style={{ background: "var(--signal)" }}
          >
            E
          </div>
          <div>
            <p className="text-[15px] font-bold leading-none" style={{ color: "var(--text)" }}>
              EASM
            </p>
            <p className="text-[11px] leading-none mt-0.5" style={{ color: "var(--muted)" }}>
              Attack Surface Dashboard
            </p>
          </div>
        </div>

        <div
          className="flex items-center gap-2 pl-3 pr-3.5 py-1.5 rounded-full"
          style={{
            background: live ? "var(--signal-dim)" : "var(--panel-alt)",
            border: `1px solid ${live ? "var(--signal)" : "var(--hairline)"}`,
          }}
        >
          <span className={`status-dot ${live ? "status-dot--live" : "status-dot--idle"}`} />
          <span
            className="text-xs font-semibold"
            style={{ color: live ? "var(--signal-hover)" : "var(--muted)" }}
          >
            {live
              ? `${activeScanCount} scan${activeScanCount === 1 ? "" : "s"} in progress`
              : "All systems clear"}
          </span>
        </div>
      </div>
    </header>
  );
}
