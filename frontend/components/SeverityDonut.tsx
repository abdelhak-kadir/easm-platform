"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { Finding, Severity } from "../types/scan";
import { SEVERITY_HEX } from "./SeverityBadge";
import { severityLabel } from "../lib/labels";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

interface Props {
  findings: Finding[];
}

export default function SeverityDonut({ findings }: Props) {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  });

  const data = ORDER.filter((s) => counts[s] > 0).map((s) => ({
    name: severityLabel(s),
    value: counts[s],
    color: SEVERITY_HEX[s],
  }));

  if (data.length === 0) return null;

  const total = findings.length;

  return (
    <div className="panel card-pad mb-6">
      <h3 className="text-sm font-bold mb-4" style={{ color: "var(--text-primary)" }}>
        Répartition par gravité
      </h3>
      <div className="flex items-center gap-6">
        <div style={{ width: 140, height: 140, position: "relative" }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={38}
                outerRadius={62}
                paddingAngle={2}
                dataKey="value"
                stroke="none"
              >
                {data.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "var(--panel)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  fontSize: 13,
                  fontFamily: "var(--font-inter)",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
          {/* Center text */}
          <div
            className="flex flex-col items-center justify-center"
            style={{
              position: "absolute",
              inset: 0,
              pointerEvents: "none",
            }}
          >
            <span
              className="text-2xl font-extrabold tabular-nums"
              style={{ color: "var(--text-primary)", fontFamily: "var(--font-manrope)" }}
            >
              {total}
            </span>
            <span className="text-[10px] font-medium mt-0.5" style={{ color: "var(--text-secondary)" }}>
              résultats
            </span>
          </div>
        </div>
        {/* Legend */}
        <div className="flex-1 space-y-1.5">
          {data.map((entry) => (
            <div key={entry.name} className="flex items-center gap-2 text-xs">
              <span
                className="w-3 h-3 rounded-full shrink-0"
                style={{ background: entry.color }}
              />
              <span style={{ color: "var(--text-primary)" }} className="font-medium">
                {entry.name}
              </span>
              <span className="tabular-nums ml-auto" style={{ color: "var(--text-secondary)" }}>
                {entry.value}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
