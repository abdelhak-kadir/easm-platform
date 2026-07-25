import { Finding } from "../types/scan";
import SeverityBadge, { SEVERITY_HEX } from "./SeverityBadge";
import CopyButton from "./CopyButton";

interface BodyProps {
  data: Record<string, any>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="text-xs w-28 shrink-0" style={{ color: "var(--muted)" }}>
        {label}
      </span>
      <span className="mono">{children}</span>
    </div>
  );
}

function HostInfoBody({ data }: BodyProps) {
  return (
    <div className="space-y-1.5">
      <Field label="IP address">
        {data.ip}
        {data.ip && <CopyButton value={data.ip} />}
      </Field>
      <Field label="Organization">
        {data.org || "unknown"}
        {data.isp && data.isp !== data.org ? ` · ISP: ${data.isp}` : ""}
      </Field>
      {data.asn && <Field label="ASN">{data.asn}</Field>}
      {(data.city || data.country_name) && (
        <Field label="Location">{[data.city, data.country_name].filter(Boolean).join(", ")}</Field>
      )}
      {data.hostnames?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-28 shrink-0 pt-0.5" style={{ color: "var(--muted)" }}>
            Hostnames
          </span>
          <div className="flex flex-wrap gap-1">
            {data.hostnames.map((h: string) => (
              <span
                key={h}
                className="mono text-xs px-2 py-0.5 rounded flex items-center gap-1"
                style={{ background: "var(--panel-alt)", border: "1px solid var(--hairline)" }}
              >
                {h}
                <CopyButton value={h} />
              </span>
            ))}
          </div>
        </div>
      )}
      {data.ports?.length > 0 && <Field label="Open ports">{data.ports.join(", ")}</Field>}
    </div>
  );
}

function OpenPortBody({ data }: BodyProps) {
  return (
    <div className="space-y-1.5">
      <Field label="Service">
        {data.product ? `${data.product}${data.version ? " " + data.version : ""}` : "unidentified"}
      </Field>
      <Field label="Endpoint">
        {data.transport}/{data.port}
        <CopyButton value={String(data.port)} />
      </Field>
      {data.banner && (
        <details className="mt-1">
          <summary className="cursor-pointer text-xs font-medium" style={{ color: "var(--signal)" }}>
            Show raw banner
          </summary>
          <pre className="code-panel mono text-xs whitespace-pre-wrap mt-2 p-3 max-h-40 overflow-y-auto">
            {data.banner}
          </pre>
        </details>
      )}
    </div>
  );
}

function VulnerabilityBody({ data }: BodyProps) {
  const color = data.cvss >= 9 ? "var(--danger)" : data.cvss >= 7 ? "var(--warning)" : "var(--text)";
  return (
    <div className="space-y-1.5">
      <Field label="CVSS score">
        <strong style={{ color }}>{data.cvss}</strong>
      </Field>
      {data.summary && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-28 shrink-0" style={{ color: "var(--muted)" }}>
            Summary
          </span>
          <p style={{ color: "var(--muted)" }}>{data.summary}</p>
        </div>
      )}
    </div>
  );
}

function DomainRegistrationBody({ data }: BodyProps) {
  return (
    <div className="space-y-1.5">
      <Field label="Domain">
        {data.domain}
        {data.domain && <CopyButton value={data.domain} />}
      </Field>
      <Field label="Registrar">{data.registrar || "unknown"}</Field>
      {data.creation_date && <Field label="Created">{data.creation_date}</Field>}
      {data.expiration_date && <Field label="Expires">{data.expiration_date}</Field>}
      {data.org && <Field label="Org">{data.org}</Field>}
      {data.country && <Field label="Country">{data.country}</Field>}
      {data.name_servers?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-28 shrink-0 pt-0.5" style={{ color: "var(--muted)" }}>
            Name servers
          </span>
          <div className="flex flex-wrap gap-1">
            {data.name_servers.map((ns: string) => (
              <span
                key={ns}
                className="mono text-xs px-2 py-0.5 rounded"
                style={{ background: "var(--panel-alt)", border: "1px solid var(--hairline)" }}
              >
                {ns}
              </span>
            ))}
          </div>
        </div>
      )}
      {data.status?.length > 0 && <Field label="Status">{data.status.join(", ")}</Field>}
      {data.emails?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-28 shrink-0 pt-0.5" style={{ color: "var(--muted)" }}>
            Emails
          </span>
          <div className="flex flex-wrap gap-1">
            {data.emails.map((e: string) => (
              <span
                key={e}
                className="mono text-xs px-2 py-0.5 rounded flex items-center gap-1"
                style={{ background: "var(--panel-alt)", border: "1px solid var(--hairline)" }}
              >
                {e}
                <CopyButton value={e} />
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function DomainExpiryBody({ data }: BodyProps) {
  const expired = data.days_remaining < 0;
  const color = expired ? "var(--danger)" : "var(--warning)";
  return (
    <div className="space-y-1.5">
      <Field label="Expiration">{data.expiration_date}</Field>
      <Field label="Days remaining">
        <strong style={{ color }}>{data.days_remaining}</strong>
      </Field>
    </div>
  );
}

// Add one entry per finding_type here to get a pretty rendering.
// Anything not registered falls back to raw JSON automatically (see
// the `Body ? <Body /> : <pre>...` below) -- so a brand new backend
// tool works immediately with zero frontend changes required. Adding
// a renderer here is purely cosmetic polish, never a blocker.
const BODY_RENDERERS: Record<string, React.ComponentType<BodyProps>> = {
  host_info: HostInfoBody,
  open_port: OpenPortBody,
  vulnerability: VulnerabilityBody,
  domain_registration: DomainRegistrationBody,
  domain_expiry: DomainExpiryBody,
};

const TYPE_TAGS: Record<string, string> = {
  host_info: "HOST",
  open_port: "PORT",
  vulnerability: "VULN",
  domain_registration: "DOMAIN",
  domain_expiry: "EXPIRY",
};

export default function FindingCard({ finding }: { finding: Finding }) {
  const Body = BODY_RENDERERS[finding.finding_type];
  const accent = SEVERITY_HEX[finding.severity] || SEVERITY_HEX.info;

  return (
    <div
      className="panel mb-3 pl-4 pr-5 py-4"
      style={{ borderLeft: `3px solid ${accent}` }}
    >
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex items-start gap-2">
          <span
            className="mono text-[10px] font-semibold tracking-wider px-1.5 py-0.5 mt-0.5 rounded"
            style={{ background: "var(--panel-alt)", color: "var(--muted)" }}
          >
            {TYPE_TAGS[finding.finding_type] || finding.finding_type.toUpperCase()}
          </span>
          <h4 className="font-semibold flex items-center gap-2">
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
        <summary className="cursor-pointer text-xs font-medium" style={{ color: "var(--signal)" }}>
          View raw JSON
        </summary>
        <pre className="code-panel mono text-xs whitespace-pre-wrap mt-2 p-3 max-h-60 overflow-y-auto">
          {JSON.stringify(finding.data, null, 2)}
        </pre>
      </details>
    </div>
  );
}
