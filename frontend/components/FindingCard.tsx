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
  if (!text) return null;
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

function EmailPresenceBody({ data }: Record<string, any>) {
  const services: { name: string; domain: string }[] = data.services || [];
  return (
    <div className="space-y-1.5">
      <Field label="Email">{data.email}{data.email && <CopyButton value={data.email} />}</Field>
      <Field label="Services">{data.total_count}</Field>
      <div className="flex items-start gap-2 text-sm">
        <span className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
          Trouvé sur
        </span>
        <div className="flex flex-wrap gap-1 max-h-36 overflow-y-auto">
          {services.map((s) => (
            <Chip key={s.name} value={s.domain || s.name} />
          ))}
        </div>
      </div>
    </div>
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

const VERDICT_META: Record<string, { label: string; color: string; bg: string }> = {
  vulnerable: { label: "❌ Vulnérable", color: "var(--critical)", bg: "var(--critical-dim)" },
  fixed: { label: "✅ Corrigé", color: "var(--success)", bg: "var(--success-dim)" },
  unknown: { label: "⚠️ À vérifier", color: "var(--high)", bg: "var(--high-dim)" },
};

function VulnerabilityBody({ data }: Record<string, any>) {
  const cvss = data.cvss ?? 0;
  const color = cvss >= 9 ? "var(--critical)" : cvss >= 7 ? "var(--high)" : "var(--text-primary)";
  const verdictMeta = data.verdict ? VERDICT_META[data.verdict] : null;
  return (
    <div className="space-y-1.5">
      {/* Fix verdict + KEV chips */}
      {(verdictMeta || data.kev) && (
        <div className="flex items-center gap-2 flex-wrap">
          {verdictMeta && (
            <span
              className="text-[11px] font-bold uppercase px-2 py-0.5 rounded-md"
              style={{
                color: verdictMeta.color,
                background: verdictMeta.bg,
                border: `1px solid ${verdictMeta.color}`,
              }}
            >
              {verdictMeta.label}
            </span>
          )}
          {data.kev && (
            <span
              className="text-[11px] font-bold uppercase px-2 py-0.5 rounded-md"
              style={{
                color: "var(--critical)",
                background: "var(--critical-dim)",
                border: "1px solid var(--critical)",
              }}
            >
              🔥 Exploité activement (CISA)
            </span>
          )}
        </div>
      )}

      {/* Verdict detail line */}
      {data.verdict && (
        <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
          {data.verdict === "vulnerable" ? (
            <>
              Version détectée <span className="mono">{data.detected_version}</span> affectée
              {data.latest_affected && (
                <> — corriger vers une version &gt; {data.latest_affected}</>
              )}
            </>
          ) : data.verdict === "fixed" ? (
            <>
              Version détectée <span className="mono">{data.detected_version}</span> corrigée
              {data.latest_affected && <> (dernière affectée : {data.latest_affected})</>}
            </>
          ) : (
            <>
              Version détectée <span className="mono">{data.detected_version}</span> hors de la
              liste des versions affectées — à vérifier
            </>
          )}
        </p>
      )}

      <Field label="CVSS">
        <span className="text-lg font-extrabold" style={{ color, fontFamily: "var(--font-manrope)" }}>
          {cvss}
        </span>
        <span className="text-xs ml-1" style={{ color: "var(--text-secondary)" }}>
          / 10
        </span>
      </Field>
      {typeof data.epss === "number" && data.epss > 0 && (
        <Field label="EPSS">
          {(data.epss * 100).toFixed(1)} %
          {typeof data.epss_ranking === "number" && data.epss_ranking > 0 && (
            <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
              {" "}
              · percentile {Math.round(data.epss_ranking * 100)}
            </span>
          )}
        </Field>
      )}
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

function HttpServiceBody({ data }: Record<string, any>) {
  const status = data.status_code;
  const ok = typeof status === "number" && status < 400;
  return (
    <div className="space-y-1.5">
      <Field label="Code HTTP">
        <span style={{ color: ok ? "var(--success)" : "var(--high)" }}>{status ?? "?"}</span>
      </Field>
      {data.title && <Field label="Titre">{data.title}</Field>}
      {data.url && (
        <Field label="URL">
          <span className="text-xs break-all">{data.url}</span>
        </Field>
      )}
      {data.server && <Field label="Serveur">{data.server}</Field>}
      {data.technologies?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
            Technologies
          </span>
          <div className="flex flex-wrap gap-1">
            {data.technologies.map((t: string) => (
              <Chip key={t} value={t} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SslCertificateBody({ data }: Record<string, any>) {
  const expired = data.expired;
  const days = data.days_left;
  const urgent = expired || (days != null && days <= 14);
  const daysColor = expired ? "var(--critical)" : urgent ? "var(--high)" : "var(--success)";
  return (
    <div className="space-y-1.5">
      <Field label="Domaine">{data.domain}{data.domain && <CopyButton value={data.domain} />}</Field>
      <Field label="Émetteur">{data.issuer || "inconnu"}</Field>
      <Field label="Valide du">{data.not_before}</Field>
      <Field label="Expire le">{data.not_after}</Field>
      <Field label="Jours restants">
        <span className="text-lg font-extrabold" style={{ color: daysColor, fontFamily: "var(--font-manrope)" }}>
          {days ?? "?"}
        </span>
      </Field>
      <Field label="Clé">{data.key_type} {data.key_size} bits</Field>
      <Field label="Signature">{data.signature_algorithm}</Field>
      {data.serial_hex && (
        <Field label="N° de série">
          <span className="text-[11px] mono break-all">{data.serial_hex}</span>
        </Field>
      )}
      {data.fingerprint_sha256 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
            Empreinte
          </span>
          <span className="text-[10px] mono break-all" style={{ color: "var(--text-primary)" }}>
            {data.fingerprint_sha256}
            <CopyButton value={data.fingerprint_sha256} />
          </span>
        </div>
      )}
      {data.sans?.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <span className="text-[11px] w-[6.5rem] shrink-0 pt-0.5 font-medium uppercase tracking-[0.04em]" style={{ color: "var(--text-secondary)" }}>
            SANs
          </span>
          <div className="flex flex-wrap gap-1">
            {data.sans.map((name: string) => (
              <Chip key={name} value={name} copy />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

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

function IpReputationBody({ data }: Record<string, any>) {
  // `rbl_listed_count` is the new name; fall back to the old `listed_count`
  // for scan results stored before the rename.
  const rblCount = data.rbl_listed_count ?? data.listed_count ?? 0;
  return (
    <div className="space-y-1.5">
      <Field label="IP">
        {data.ip}
        {data.ip && <CopyButton value={data.ip} />}
      </Field>
      <Field label="Zones vérifiées">{data.zones_checked ?? 0}</Field>
      <Field label="Blacklists RBL">
        <span style={{ color: rblCount > 0 ? "var(--critical)" : "var(--success)" }}>
          {rblCount > 0 ? `${rblCount} liste${rblCount > 1 ? "s" : ""}` : "aucune"}
        </span>
      </Field>
      {typeof data.abuseipdb_score === "number" && (
        <Field label="Signalé AbuseIPDB">
          <span
            style={{
              color: data.abuseipdb_reported ? "var(--critical)" : "var(--success)",
            }}
          >
            {data.abuseipdb_reported
              ? `oui — score ${data.abuseipdb_score}/100`
              : "non"}
          </span>
        </Field>
      )}
      {typeof data.tor_exit === "boolean" && (
        <Field label="Exit Tor">
          <span style={{ color: data.tor_exit ? "var(--high)" : "var(--text-primary)" }}>
            {data.tor_exit ? "oui — point de sortie Tor" : "non"}
          </span>
        </Field>
      )}
      {(data.zones_with_errors ?? 0) > 0 && (
        <p className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
          {data.zones_with_errors} zone(s) non vérifiée(s) (erreur DNS)
        </p>
      )}
    </div>
  );
}

function RblListingBody({ data }: Record<string, any>) {
  return (
    <div className="space-y-1.5">
      <Field label="Liste">{data.zone}</Field>
      {data.code && (
        <Field label="Code">
          <span className="mono text-xs">{data.code}</span>
        </Field>
      )}
      {data.reason && <Field label="Raison">{data.reason}</Field>}
      {data.query && (
        <Field label="Requête">
          <span className="text-xs mono break-all">{data.query}</span>
        </Field>
      )}
    </div>
  );
}

function AbuseipdbReportBody({ data }: Record<string, any>) {
  const score = data.score ?? 0;
  const color = score >= 70 ? "var(--critical)" : score >= 30 ? "var(--high)" : "var(--text-primary)";
  return (
    <div className="space-y-1.5">
      <Field label="Score">
        <span className="text-lg font-extrabold" style={{ color, fontFamily: "var(--font-manrope)" }}>
          {score}
        </span>
        <span className="text-xs ml-1" style={{ color: "var(--text-secondary)" }}>
          / 100
        </span>
      </Field>
      <Field label="Signalements">{data.total_reports ?? 0}</Field>
      <Field label="Utilisateurs distincts">{data.distinct_users ?? 0}</Field>
      {data.last_reported_at && (
        <Field label="Dernier signalement">
          {new Date(data.last_reported_at).toLocaleDateString("fr-FR")}
        </Field>
      )}
      {data.usage_type && <Field label="Type d'usage">{data.usage_type}</Field>}
      {data.isp && <Field label="FAI">{data.isp}</Field>}
      {data.country_code && <Field label="Pays">{data.country_code}</Field>}
      {typeof data.is_whitelisted === "boolean" && (
        <Field label="Whitelisté">
          <span style={{ color: data.is_whitelisted ? "var(--success)" : "var(--text-primary)" }}>
            {data.is_whitelisted ? "oui" : "non"}
          </span>
        </Field>
      )}
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
  http_service: HttpServiceBody,
  email_presence: EmailPresenceBody,
  ssl_certificate: SslCertificateBody,
  ip_reputation: IpReputationBody,
  rbl_listing: RblListingBody,
  abuseipdb_report: AbuseipdbReportBody,
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
