import { useState } from "react";

export default function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy(e: React.MouseEvent) {
    e.stopPropagation();
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }

  return (
    <button
      onClick={handleCopy}
      className="mono text-[10px] tracking-wider px-1.5 py-0.5 rounded border transition-colors"
      style={{
        borderColor: copied ? "var(--success)" : "var(--hairline)",
        color: copied ? "var(--success)" : "var(--muted)",
        background: copied ? "var(--success-dim)" : "var(--panel)",
      }}
      title={`copy "${value}"`}
    >
      {copied ? "done" : "copy"}
    </button>
  );
}
