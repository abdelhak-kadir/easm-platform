"use client";

import { useState, useCallback, useEffect, createContext, useContext } from "react";

type ToastVariant = "success" | "error" | "info";

interface ToastItem {
  id: number;
  message: string;
  variant: ToastVariant;
  exiting: boolean;
}

interface ToastContextValue {
  success: (msg: string) => void;
  error: (msg: string) => void;
  info: (msg: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

let _nextId = 0;
let _listeners: Array<(item: ToastItem) => void> = [];

function emit(variant: ToastVariant, message: string) {
  const item: ToastItem = { id: ++_nextId, message, variant, exiting: false };
  _listeners.forEach((fn) => fn(item));
}

export function showToast(message: string, variant: ToastVariant = "info") {
  emit(variant, message);
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (ctx) return ctx;
  // Fallback for components outside the provider (still works via module emitter)
  return {
    success: (msg: string) => emit("success", msg),
    error: (msg: string) => emit("error", msg),
    info: (msg: string) => emit("info", msg),
  };
}

const ICON: Record<ToastVariant, string> = {
  success: "✓",
  error: "✗",
  info: "ℹ",
};

const TOAST_COLORS: Record<ToastVariant, { color: string; bg: string; border: string }> = {
  success: { color: "var(--success)", bg: "var(--success-dim)", border: "var(--success)" },
  error: { color: "var(--critical)", bg: "var(--critical-dim)", border: "var(--critical)" },
  info: { color: "var(--brand-accent)", bg: "var(--brand-dim)", border: "var(--brand-accent)" },
};

export function ToastContainer() {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  useEffect(() => {
    const handler = (item: ToastItem) => {
      setToasts((prev) => [...prev, item]);
    };
    _listeners.push(handler);
    return () => {
      _listeners = _listeners.filter((h) => h !== handler);
    };
  }, []);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, exiting: true } : t)));
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 300);
  }, []);

  // Auto-dismiss
  useEffect(() => {
    if (toasts.length === 0) return;
    const latest = toasts[toasts.length - 1];
    if (latest.exiting) return;
    const delay = latest.variant === "error" ? 6000 : 4000;
    const timer = setTimeout(() => dismiss(latest.id), delay);
    return () => clearTimeout(timer);
  }, [toasts, dismiss]);

  // Escape dismisses top toast
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape" && toasts.length > 0) {
        const top = toasts[toasts.length - 1];
        dismiss(top.id);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [toasts, dismiss]);

  if (toasts.length === 0) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label="Notifications"
      className="toast-container"
    >
      {toasts.map((t) => {
        const c = TOAST_COLORS[t.variant];
        return (
          <div
            key={t.id}
            className={`toast-item ${t.exiting ? "toast-exit" : "toast-enter"}`}
            style={{
              color: c.color,
              background: c.bg,
              border: `1px solid ${c.border}`,
            }}
          >
            <span className="toast-icon">{ICON[t.variant]}</span>
            <span className="toast-message">{t.message}</span>
            <button
              onClick={() => dismiss(t.id)}
              className="toast-close"
              aria-label="Fermer"
            >
              &times;
            </button>
          </div>
        );
      })}
    </div>
  );
}
