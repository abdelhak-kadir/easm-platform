"use client";

import { useState, useEffect } from "react";

type Props = {
  activeScanCount: number;
  selectedAssetValue: string | null;
  onTriggerScan?: () => void;
  scanning?: boolean;
  onBackToDashboard?: () => void;
};

function getInitialTheme(): "light" | "dark" {
  if (typeof window === "undefined") return "light";
  const stored = localStorage.getItem("easm-theme");
  if (stored === "dark" || stored === "light") return stored;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export default function TopNav({
  activeScanCount,
  selectedAssetValue,
  onTriggerScan,
  scanning,
  onBackToDashboard,
}: Props) {
  const live = activeScanCount > 0;
  const [theme, setTheme] = useState<"light" | "dark">("light");

  useEffect(() => {
    const initial = getInitialTheme();
    setTheme(initial);
    document.documentElement.setAttribute("data-theme", initial);
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("easm-theme", next);
  }

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
          {/* EASM home link */}
          <button
            onClick={onBackToDashboard}
            className="text-sm font-extrabold transition-colors hover:opacity-70"
            style={{ color: "var(--brand-accent)", fontFamily: "var(--font-manrope)" }}
          >
            EASM
          </button>

          {selectedAssetValue ? (
            <>
              <span style={{ color: "var(--border)" }}>|</span>
              <button
                onClick={onBackToDashboard}
                className="flex items-center gap-1.5 transition-colors hover:opacity-70"
              >
                <span className="text-[10px]" style={{ color: "var(--text-secondary)" }}>←</span>
                <span className="text-[10px] font-semibold uppercase tracking-wider"
                  style={{ color: "var(--text-secondary)" }}>
                  Cible
                </span>
                <span className="mono text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                  {selectedAssetValue}
                </span>
              </button>
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

        {/* Right: theme + global status */}
        <div className="flex items-center gap-3">
          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            className="w-8 h-8 rounded-full flex items-center justify-center text-sm transition-colors"
            style={{
              background: "var(--panel-dim)",
              border: "1px solid var(--border)",
              color: "var(--text-secondary)",
            }}
            title={theme === "dark" ? "Mode clair" : "Mode sombre"}
            aria-label={theme === "dark" ? "Activer le mode clair" : "Activer le mode sombre"}
          >
            {theme === "dark" ? "☀" : "☾"}
          </button>

          {/* Status */}
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
      </div>
    </header>
  );
}
