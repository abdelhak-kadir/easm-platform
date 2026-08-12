"use client";

import { Component, ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[ErrorBoundary]", error.message, info.componentStack?.slice(0, 300));
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;
      return (
        <div
          className="panel p-6 text-center space-y-3"
          style={{ maxWidth: 480, margin: "40px auto" }}
        >
          <p className="text-sm font-semibold" style={{ color: "var(--critical)" }}>
            Une erreur est survenue
          </p>
          <p
            className="text-[11px] font-mono break-all"
            style={{ color: "var(--text-secondary)" }}
          >
            {this.state.error?.message || "Erreur inconnue"}
          </p>
          <button
            className="btn-primary text-xs"
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            Réessayer
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
