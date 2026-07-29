import { Finding } from "../types/scan";
import SeverityBadge, { SEVERITY_HEX } from "./SeverityBadge";
import CopyButton from "./CopyButton";
import { findingTypeLabel, FINDING_TYPE_DESCRIPTION, SEVERITY_EXPLAINER } from "../lib/labels";

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
      <Field label="Adresse IP">
        {data.ip}
        {data.ip && <CopyButton value={data.ip} />}
      </Field>
      <Field label="Organisation">
        {data.org || "inconnue"}
        {data.isp && data.isp !== data.org ? ` · FAI : ${data.isp}` : ""}
      </Field>
      {data.asn && <Field label="ASN">{data.asn}</Field>}
      {(data.city || data.country_name) && (
        <Field label="Localisation">{[data.city, data.country_name].filter(Boolean).join(", ")}</Field>
      )}
      {data.hostnames?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-28 shrink-0 pt-0.5" style={{ color: "var(--muted)" }}>
            Noms d'hôte
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
      {data.ports?.length > 0 && <Field label="Ports ouverts">{data.ports.join(", ")}</Field>}
    </div>
  );
}

function OpenPortBody({ data }: BodyProps) {
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
        <details className="mt-1">
          <summary className="cursor-pointer text-xs font-medium" style={{ color: "var(--signal)" }}>
            Afficher la bannière brute
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
      <Field label="Score de risque">
        <strong style={{ color }}>{data.cvss}</strong>
        <span className="text-xs ml-1" style={{ color: "var(--muted)" }}>
          / 10
        </span>
      </Field>
      {data.summary && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-28 shrink-0" style={{ color: "var(--muted)" }}>
            Résumé
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
      <Field label="Domaine">
        {data.domain}
        {data.domain && <CopyButton value={data.domain} />}
      </Field>
      <Field label="Registraire">{data.registrar || "inconnu"}</Field>
      {data.creation_date && <Field label="Créé le">{data.creation_date}</Field>}
      {data.expiration_date && <Field label="Expire le">{data.expiration_date}</Field>}
      {data.org && <Field label="Organisation">{data.org}</Field>}
      {data.country && <Field label="Pays">{data.country}</Field>}
      {data.name_servers?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-28 shrink-0 pt-0.5" style={{ color: "var(--muted)" }}>
            Serveurs de noms
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
      {data.status?.length > 0 && <Field label="Statut">{data.status.join(", ")}</Field>}
      {data.emails?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-28 shrink-0 pt-0.5" style={{ color: "var(--muted)" }}>
            E-mails
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
      <Field label="Jours restants">
        <strong style={{ color }}>{data.days_remaining}</strong>
      </Field>
    </div>
  );
}

function ReverseDnsBody({ data }: BodyProps) {
  return (
    <div className="space-y-1.5">
      <Field label="ip address">
        {data.ip}
        {data.ip && <CopyButton value={data.ip} />}
      </Field>
      {data.hostnames?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-xs w-24 shrink-0 pt-0.5" style={{ color: "var(--muted)" }}>
            hostnames
          </span>
          <div className="flex flex-wrap gap-1">
            {data.hostnames.map((h: string) => (
              <span key={h} className="mono text-xs px-2 py-0.5 flex items-center gap-1"
                style={{ background: "var(--panel-alt)", border: "1px solid var(--hairline)" }}>
                {h}
                <CopyButton value={h} />
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
// Ajoutez une entrée par finding_type ici pour un rendu soigné. Tout type
// non enregistré retombe automatiquement sur le JSON brut (voir le
// `Body ? <Body /> : <pre>...` plus bas) -- un nouvel outil backend
// fonctionne donc immédiatement, sans aucune modification frontend
// nécessaire. Ajouter un rendu ici n'est qu'une amélioration cosmétique.
const BODY_RENDERERS: Record<string, React.ComponentType<BodyProps>> = {
  host_info: HostInfoBody,
  open_port: OpenPortBody,
  vulnerability: VulnerabilityBody,
  domain_registration: DomainRegistrationBody,
  domain_expiry: DomainExpiryBody,
  reverse_dns: ReverseDnsBody,
};

export default function FindingCard({ finding }: { finding: Finding }) {
  const Body = BODY_RENDERERS[finding.finding_type];
  const accent = SEVERITY_HEX[finding.severity] || SEVERITY_HEX.info;
  const explainer = SEVERITY_EXPLAINER[finding.severity];

  return (
    <div
      className="panel mb-3 pl-4 pr-5 py-4"
      style={{ borderLeft: `3px solid ${accent}` }}
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <div>
          <p className="eyebrow mb-1" title={FINDING_TYPE_DESCRIPTION[finding.finding_type]}>
            {findingTypeLabel(finding.finding_type)}
          </p>
          <h4 className="font-semibold flex items-center gap-2">
            {finding.title}
            <CopyButton value={finding.title} />
          </h4>
        </div>
        <SeverityBadge severity={finding.severity} />
      </div>

      {explainer && (
        <p className="text-xs mb-3" style={{ color: "var(--muted)" }}>
          {explainer}
        </p>
      )}

      {Body ? (
        <Body data={finding.data} />
      ) : (
        <pre className="mono text-xs whitespace-pre-wrap" style={{ color: "var(--muted)" }}>
          {JSON.stringify(finding.data, null, 2)}
        </pre>
      )}

      <details className="mt-3">
        <summary className="cursor-pointer text-xs font-medium" style={{ color: "var(--muted)" }}>
          Détails techniques <span style={{ color: "var(--faint)" }}>(pour les équipes sécurité)</span>
        </summary>
        <pre className="code-panel mono text-xs whitespace-pre-wrap mt-2 p-3 max-h-60 overflow-y-auto">
          {JSON.stringify(finding.data, null, 2)}
        </pre>
      </details>
    </div>
  );
}
