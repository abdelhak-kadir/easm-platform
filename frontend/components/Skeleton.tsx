"use client";

/** Skeleton loader with CSS shimmer animation. */

interface Props {
  variant?: "text" | "card" | "list";
  width?: string;
  height?: string;
  count?: number;
  className?: string;
}

export default function Skeleton({
  variant = "text",
  width,
  height,
  count = 1,
  className = "",
}: Props) {
  const items = Array.from({ length: count }, (_, i) => i);

  if (variant === "card") {
    return (
      <>
        {items.map((i) => (
          <div
            key={i}
            className={`skeleton-shimmer rounded-xl ${className}`}
            style={{
              width: width || "100%",
              height: height || "120px",
              background: "var(--skeleton-bg)",
            }}
          />
        ))}
      </>
    );
  }

  if (variant === "list") {
    return (
      <div className={`space-y-2 ${className}`}>
        {items.map((i) => (
          <div
            key={i}
            className="skeleton-shimmer rounded-lg flex items-center gap-3 px-4 py-3"
            style={{ background: "var(--skeleton-bg)", height: height || "48px" }}
          >
            <div
              className="rounded-full shrink-0"
              style={{
                width: 8,
                height: 8,
                background: "var(--skeleton-highlight)",
              }}
            />
            <div
              className="rounded flex-1"
              style={{
                height: 12,
                background: "var(--skeleton-highlight)",
              }}
            />
            <div
              className="rounded-full shrink-0"
              style={{
                width: 64,
                height: 20,
                background: "var(--skeleton-highlight)",
              }}
            />
          </div>
        ))}
      </div>
    );
  }

  // text variant
  return (
    <>
      {items.map((i) => (
        <div
          key={i}
          className={`skeleton-shimmer rounded ${className}`}
          style={{
            width: width || "100%",
            height: height || "14px",
            background: "var(--skeleton-bg)",
          }}
        />
      ))}
    </>
  );
}
