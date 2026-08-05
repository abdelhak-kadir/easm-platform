"use client";

import { ScanJob, Finding } from "../types/scan";
import { explainTool } from "../lib/explanations";
import { toolLabel } from "../lib/labels";

interface Props {
  job: ScanJob;
  findings?: Finding[];
}

export default function ToolExplainer({ job, findings = [] }: Props) {
  const text = explainTool(job, findings.length);

  return (
    <div className="panel px-5 py-4 mb-5" style={{ borderLeft: "3px solid var(--brand-accent)" }}>
      <p className="eyebrow mb-1.5">{toolLabel(job.tool)} ce que fait cet outil</p>
      <p className="text-sm" style={{ color: "var(--text-primary)" }}>
        {text}
      </p>
    </div>
  );
}
