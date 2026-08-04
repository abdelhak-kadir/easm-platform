"use client";

import { useState } from "react";
import { Finding } from "../types/scan";
import SeverityBadge, { SEVERITY_HEX } from "./SeverityBadge";
import CopyButton from "./CopyButton";
import { findingTypeLabel, FINDING_TYPE_DESCRIPTION, SEVERITY_EXPLAINER } from "../lib/labels";
import { explainFinding } from "../lib/explanations";

/* ── shared chip / field atoms ────────────────────────────────────────── */

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-sm">
      <span
        className="text-[11px] w-[6.5rem] shrink-0 font-medium uppercase tracking-[0.04em]"
        style={{ color: "var(--text-secondary)" }}
      >
        {label}
      </span>
      <span className="font-medium" style={{ color: "var(--text-primary)" }}>
        {children}
      </span>
    </div>
  );
}

function Chip({ value, copy }: { value: string; copy?: boolean }) {
  return (
    <span
      className="inline-flex items-center gap-1 text-[12px] px-2 py-0.5 rounded-md font-medium"
      style={{
        background: "var(--panel-dim)",
        border: "1px solid var(--border)",
        color: "var(--text-primary)",
      }}
    >
      {value}
      {copy && <CopyButton value={value} />}
    </span>
  );
}

/* ── explanation block (new) ─────────────────────────────────────────── */

function ExplanationBlock({ finding }: { finding: Finding }) {
  const text = explainFinding(finding);
  return (
    <p
      className="text-[13px] leading-relaxed mb-3 px-3 py-2.5 rounded-md"
      style={{
        color: "var(--text-primary)",
        background: "var(--panel-dim)",
        border: "1px solid var(--border)",
      }}
    >
      {text}
    </p>
  );
}

/* ── body renderers per finding_type ─────────────────────────────────── */

function HostInfoBody({ data }: Record<string, any>) {
  return (
    <div className="space-y-1.5">
      <Field label="IP">
        {data.ip}
        {data.ip && <CopyButton value={data.ip} />}
      </Field>
      <Field label="Organisation">
        {data.org || "inconnue"}
        {data.isp && data.isp !== data.org ? ` · ${data.isp}` : ""}
      </Field>
      {data.asn && <Field label="ASN">{data.asn}</Field>}
      {(data.city || data.country_name) && (
        <Field label="Localisation">
          {[data.city, data.region_code, data.country_name].filter(Boolean).join(", ")}
        </Field>
      )}
      {data.hostnames?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span
            className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]"
            style={{ color: "var(--text-secondary)" }}
          >
            Hôtes
          </span>
          <div className="flex flex-wrap gap-1">
            {data.hostnames.map((h: string) => (
              <Chip key={h} value={h} copy />
            ))}
          </div>
        </div>
      )}
      {data.ports?.length > 0 && (
        <Field label="Ports">{data.ports.join(", ")}</Field>
      )}
    </div>
  );
}

function OpenPortBody({ data }: Record<string, any>) {
  return (
    <div className="space-y-1.5">
      <Field label="Service">
        {data.product ? `${data.product}${data.version ? " " + data.version : ""}` : "non identifié"}
      </Field>
      <Field label="Adresse">
        {data.transport}/{data.port}
        <CopyButton value={String(data.port)} />
      </Field>
      {data.banner && (
        <details className="mt-2">
          <summary
            className="cursor-pointer text-xs font-semibold inline-flex items-center gap-1"
            style={{ color: "var(--brand-accent)" }}
          >
            Bannière brute
          </summary>
          <pre className="code-panel text-xs whitespace-pre-wrap mt-2 p-3 max-h-40 overflow-y-auto rounded-md">
            {data.banner}
          </pre>
        </details>
      )}
    </div>
  );
}

function VulnerabilityBody({ data }: Record<string, any>) {
  const cvss = data.cvss ?? 0;
  const color = cvss >= 9 ? "var(--critical)" : cvss >= 7 ? "var(--high)" : "var(--text-primary)";
  return (
    <div className="space-y-1.5">
      <Field label="CVSS">
        <span className="text-lg font-extrabold" style={{ color, fontFamily: "var(--font-manrope)" }}>
          {cvss}
        </span>
        <span className="text-xs ml-1" style={{ color: "var(--text-secondary)" }}>
          / 10
        </span>
      </Field>
      {data.summary && (
        <div className="flex items-start gap-2 text-sm">
          <span
            className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]"
            style={{ color: "var(--text-secondary)" }}
          >
            Résumé
          </span>
          <p style={{ color: "var(--text-secondary)", fontSize: "13px" }}>{data.summary}</p>
        </div>
      )}
    </div>
  );
}

function DomainRegistrationBody({ data }: Record<string, any>) {
  return (
    <div className="space-y-1.5">
      <Field label="Domaine">{data.domain}{data.domain && <CopyButton value={data.domain} />}</Field>
      <Field label="Registraire">{data.registrar || "inconnu"}</Field>
      {data.creation_date && <Field label="Créé le">{data.creation_date}</Field>}
      {data.expiration_date && <Field label="Expire le">{data.expiration_date}</Field>}
      {data.org && <Field label="Organisation">{data.org}</Field>}
      {data.country && <Field label="Pays">{data.country}</Field>}
      {data.name_servers?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
            NS
          </span>
          <div className="flex flex-wrap gap-1">
            {data.name_servers.map((ns: string) => (
              <Chip key={ns} value={ns} />
            ))}
          </div>
        </div>
      )}
      {data.emails?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
            E-mails
          </span>
          <div className="flex flex-wrap gap-1">
            {data.emails.map((e: string) => (
              <Chip key={e} value={e} copy />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function DomainExpiryBody({ data }: Record<string, any>) {
  const expired = data.days_remaining < 0;
  const color = expired ? "var(--critical)" : "var(--high)";
  return (
    <div className="space-y-1.5">
      <Field label="Expiration">{data.expiration_date}</Field>
      <Field label="Jours restants">
        <span className="text-lg font-extrabold" style={{ color, fontFamily: "var(--font-manrope)" }}>
          {data.days_remaining}
        </span>
      </Field>
    </div>
  );
}

function ReverseDnsBody({ data }: Record<string, any>) {
  return (
    <div className="space-y-1.5">
      <Field label="IP">{data.ip}{data.ip && <CopyButton value={data.ip} />}</Field>
      {data.hostnames?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
            Hostnames
          </span>
          <div className="flex flex-wrap gap-1">
            {data.hostnames.map((h: string) => (
              <Chip key={h} value={h} copy />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function EmailSecurityBody({ data }: Record<string, any>) {
  return (
    <div className="space-y-1.5">
      <Field label="Vérification">{data.check?.toUpperCase()}</Field>
      <Field label="Présent">{data.present ? "oui" : "non"}</Field>
      {data.policy && <Field label="Politique">{data.policy}</Field>}
      {data.record && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
            Enregistrement
          </span>
          <span className="text-xs break-all" style={{ color: "var(--text-primary)" }}>
            {data.record}
          </span>
        </div>
      )}
    </div>
  );
}

const CATEGORY_LABEL: Record<string, string> = {
  emails: "E-mails", hosts: "Noms d'hôte", ips: "Adresses IP", urls: "URLs",
};

function DiscoveredAssetsBody({ data }: Record<string, any>) {
  const items: string[] = data.items || [];
  const category = data.category || "";
  const label = CATEGORY_LABEL[category] || category;
  return (
    <div className="space-y-1.5">
      <Field label="Catégorie">{label}</Field>
      <Field label="Trouvés">{items.length}</Field>
      <div className="flex items-start gap-2 text-sm">
        <span className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
          Éléments
        </span>
        <div className="flex flex-wrap gap-1 max-h-36 overflow-y-auto">
          {items.slice(0, 50).map((item: string) => (
            <Chip key={item} value={item} copy />
          ))}
          {items.length > 50 && (
            <span className="text-xs self-center" style={{ color: "var(--text-secondary)" }}>
              +{items.length - 50} autres
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

const BODY_RENDERERS: Record<string, React.ComponentType<{ data: Record<string, any> }>> = {
  host_info: HostInfoBody,
  open_port: OpenPortBody,
  vulnerability: VulnerabilityBody,
  domain_registration: DomainRegistrationBody,
  domain_expiry: DomainExpiryBody,
  reverse_dns: ReverseDnsBody,
  email_security: EmailSecurityBody,
  discovered_assets: DiscoveredAssetsBody,
};

/* ── FindingCard ──────────────────────────────────────────────────────── */

export default function FindingCard({ finding }: { finding: Finding }) {
  const Body = BODY_RENDERERS[finding.finding_type];
  const accent = SEVERITY_HEX[finding.severity] || SEVERITY_HEX.info;
  const explainer = SEVERITY_EXPLAINER[finding.severity];
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="panel mb-3 overflow-hidden"
      style={{ borderLeft: `3px solid ${accent}` }}
    >
      {/* Header */}
      <div className="px-4 py-3 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span
              className="text-[10px] font-bold uppercase tracking-[0.08em]"
              style={{ color: accent }}
              title={FINDING_TYPE_DESCRIPTION[finding.finding_type]}
            >
              {findingTypeLabel(finding.finding_type)}
            </span>
          </div>
          <h4 className="text-sm font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            {finding.title}
            <CopyButton value={finding.title} />
          </h4>
          {explainer && (
            <p className="text-[12px] mt-1" style={{ color: "var(--text-secondary)" }}>
              {explainer}
            </p>
          )}
        </div>
        <SeverityBadge severity={finding.severity} />
      </div>

      {/* Explanation + Body */}
      <div className="px-4 pb-3" style={{ borderTop: "1px solid var(--border)", paddingTop: "0.75rem" }}>
        <ExplanationBlock finding={finding} />
        {Body ? (
          <Body data={finding.data} />
        ) : (
          <pre className="text-xs whitespace-pre-wrap" style={{ color: "var(--text-secondary)" }}>
            {JSON.stringify(finding.data, null, 2)}
          </pre>
        )}
      </div>

      {/* Technical details (collapsible) */}
      <div style={{ borderTop: "1px solid var(--border)" }}>
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full px-4 py-2 text-left flex items-center justify-between text-[11px] font-semibold uppercase tracking-[0.05em] transition-colors hover:bg-[var(--panel-dim)]"
          style={{ color: "var(--text-secondary)" }}
        >
          <span>Détails techniques</span>
          <span
            style={{
              transform: expanded ? "rotate(180deg)" : "rotate(0deg)",
              transition: "transform 0.2s ease",
              fontSize: "10px",
            }}
          >
            ▼
          </span>
        </button>
        {expanded && (
          <div className="px-4 pb-3">
            <pre className="code-panel text-xs whitespace-pre-wrap p-3 max-h-72 overflow-y-auto rounded-md">
              {JSON.stringify(finding.data, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
