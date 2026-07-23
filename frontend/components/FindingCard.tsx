import { Finding } from "../types/scan";
import SeverityBadge, { SEVERITY_HEX } from "./SeverityBadge";
import CopyButton from "./CopyButton";

interface BodyProps {
  data: Record<string, any>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="text-xs w-24 shrink-0" style={{ color: "var(--muted)" }}>
        {label}
      </span>
      <span className="mono">{children}</span>
    </div>
  );
}

function HostInfoBody({ data }: BodyProps) {
  return (
    <div className="space-y-1.5">
      <Field label="ip address">
        {data.ip}
        {data.ip && <CopyButton value={data.ip} />}
      </Field>
      <Field label="organization">
        {data.org || "unknown"}
        {data.isp && data.isp !== data.org ? ` · isp: ${data.isp}` : ""}
      </Field>
      {data.asn && <Field label="asn">{data.asn}</Field>}
      {(data.city || data.country_name) && (
        <Field label="location">{[data.city, data.country_name].filter(Boolean).join(", ")}</Field>
      )}
      {data.hostnames?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-24 shrink-0 pt-0.5" style={{ color: "var(--muted)" }}>
            hostnames
          </span>
          <div className="flex flex-wrap gap-1">
            {data.hostnames.map((h: string) => (
              <span
                key={h}
                className="mono text-xs px-2 py-0.5 flex items-center gap-1"
                style={{ background: "var(--panel-alt)", border: "1px solid var(--hairline)" }}
              >
                {h}
                <CopyButton value={h} />
              </span>
            ))}
          </div>
        </div>
      )}
      {data.ports?.length > 0 && <Field label="open ports">{data.ports.join(", ")}</Field>}
    </div>
  );
}

function OpenPortBody({ data }: BodyProps) {
  return (
    <div className="space-y-1.5">
      <Field label="service">
        {data.product ? `${data.product}${data.version ? " " + data.version : ""}` : "unidentified"}
      </Field>
      <Field label="endpoint">
        {data.transport}/{data.port}
        <CopyButton value={String(data.port)} />
      </Field>
      {data.banner && (
        <details className="mt-1">
          <summary className="mono cursor-pointer text-xs" style={{ color: "var(--muted)" }}>
            show raw banner
          </summary>
          <pre
            className="mono text-xs whitespace-pre-wrap mt-1 p-2 max-h-40 overflow-y-auto"
            style={{ background: "var(--ink)", border: "1px solid var(--hairline)", color: "var(--muted)" }}
          >
            {data.banner}
          </pre>
        </details>
      )}
    </div>
  );
}

function VulnerabilityBody({ data }: BodyProps) {
  const color = data.cvss >= 9 ? "#E0525C" : data.cvss >= 7 ? "#E08A4B" : "var(--text)";
  return (
    <div className="space-y-1.5">
      <Field label="cvss score">
        <strong style={{ color }}>{data.cvss}</strong>
      </Field>
      {data.summary && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-24 shrink-0" style={{ color: "var(--muted)" }}>
            summary
          </span>
          <p style={{ color: "var(--muted)" }}>{data.summary}</p>
        </div>
      )}
    </div>
  );
}

const BODY_RENDERERS: Record<string, React.ComponentType<BodyProps>> = {
  host_info: HostInfoBody,
  open_port: OpenPortBody,
  vulnerability: VulnerabilityBody,
};

const TYPE_TAGS: Record<string, string> = {
  host_info: "HOST",
  open_port: "PORT",
  vulnerability: "VULN",
};

export default function FindingCard({ finding }: { finding: Finding }) {
  const Body = BODY_RENDERERS[finding.finding_type];
  const accent = SEVERITY_HEX[finding.severity] || SEVERITY_HEX.info;

  return (
    <div
      className="mb-3 pl-4 pr-4 py-4"
      style={{ background: "var(--panel)", borderLeft: `3px solid ${accent}`, borderRadius: "var(--radius)" }}
    >
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex items-start gap-2">
          <span
            className="mono text-[10px] tracking-wider px-1.5 py-0.5 mt-0.5"
            style={{ background: "var(--panel-alt)", color: "var(--muted)" }}
          >
            {TYPE_TAGS[finding.finding_type] || finding.finding_type.toUpperCase()}
          </span>
          <h4 className="font-medium flex items-center gap-2">
            {finding.title}
            <CopyButton value={finding.title} />
          </h4>
        </div>
        <SeverityBadge severity={finding.severity} />
      </div>

      {Body ? (
        <Body data={finding.data} />
      ) : (
        <pre className="mono text-xs whitespace-pre-wrap" style={{ color: "var(--muted)" }}>
          {JSON.stringify(finding.data, null, 2)}
        </pre>
      )}

      <details className="mt-3">
        <summary className="mono cursor-pointer text-xs" style={{ color: "var(--muted)" }}>
          view raw json
        </summary>
        <pre
          className="mono text-xs whitespace-pre-wrap mt-1 p-2 max-h-60 overflow-y-auto"
          style={{ background: "var(--ink)", border: "1px solid var(--hairline)", color: "var(--muted)" }}
        >
          {JSON.stringify(finding.data, null, 2)}
        </pre>
      </details>
    </div>
  );
}
