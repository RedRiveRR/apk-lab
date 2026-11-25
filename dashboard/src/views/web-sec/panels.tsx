/**
 * Drill-down panels for the Web Sec Lab workbench.
 *
 * The engine report carries every module's own `data` object; these panels turn
 * the known families (WHOIS, DNS, certificate, headers/cookies, ports, SEO,
 * technologies, contacts, subdomains, content and secrets, takeover, origin,
 * framework data) into tables and chips, and fall back to a generic renderer so a
 * module without a dedicated panel still gets one. Data is untyped engine JSON,
 * so every panel reads defensively.
 */
import type { ComponentType, ReactNode } from "react";
import type { WebSecModuleOutcome } from "../../lib/api";

type Data = Record<string, unknown>;

const str = (value: unknown): string =>
  value === null || value === undefined ? "" : String(value);

const asList = (value: unknown): unknown[] =>
  Array.isArray(value) ? value : value === null || value === undefined || value === "" ? [] : [value];

const yesNo = (value: unknown): string => (value ? "yes" : "no");

const scalar = (value: unknown): string =>
  typeof value === "boolean" ? yesNo(value) : str(value);

const isEmpty = (value: unknown): boolean =>
  value === null ||
  value === undefined ||
  value === "" ||
  (Array.isArray(value) && value.length === 0) ||
  (typeof value === "object" && !Array.isArray(value) && Object.keys(value as Data).length === 0);

function Row({ label, value }: { label: string; value: ReactNode }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex flex-wrap gap-x-3 gap-y-0.5">
      <span className="min-w-44 shrink-0 text-(--iux-muted-foreground)">{label}</span>
      <span className="min-w-0 break-all">{value}</span>
    </div>
  );
}

function Chips({ values }: { values: string[] }) {
  if (!values.length) return null;
  return (
    <span className="flex flex-wrap gap-1">
      {values.map((value, index) => (
        <span key={`${value}-${index}`} className="rounded border border-(--iux-border) px-1.5 py-0.5">
          {value}
        </span>
      ))}
    </span>
  );
}

function Table({ head, rows }: { head: string[]; rows: ReactNode[][] }) {
  if (!rows.length) return null;
  return (
    <table className="w-full text-start text-xs">
      <thead>
        <tr className="text-(--iux-muted-foreground)">
          {head.map((cell) => (
            <th key={cell} className="py-1 pe-3 font-medium">{cell}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, index) => (
          <tr key={index} className="border-t border-(--iux-border)">
            {row.map((cell, cellIndex) => (
              <td key={cellIndex} className="py-1 pe-3 align-top">{cell}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SubSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <h4 className="text-xs font-semibold uppercase tracking-wide text-(--iux-muted-foreground)">{title}</h4>
      {children}
    </div>
  );
}

/** Recursive fallback: scalars as rows, scalar lists as chips, object lists as tables, nested objects indented. */
function GenericEntries({ data, depth = 0 }: { data: Data; depth?: number }) {
  return (
    <div className="space-y-1">
      {Object.entries(data).filter(([, value]) => !isEmpty(value)).map(([key, value]) => (
        <GenericEntry key={key} label={key} value={value} depth={depth} />
      ))}
    </div>
  );
}

function GenericEntry({ label, value, depth }: { label: string; value: unknown; depth: number }) {
  if (isEmpty(value)) return null;
  if (Array.isArray(value)) {
    if (value.every((item) => typeof item !== "object" || item === null)) {
      return <Row label={label} value={<Chips values={value.map((item) => scalar(item))} />} />;
    }
    const records = value.map((item) =>
      item && typeof item === "object" ? (item as Data) : ({ value: item } as Data));
    const head = [...new Set(records.flatMap((record) => Object.keys(record)))];
    return (
      <div className="space-y-1">
        <span className="text-(--iux-muted-foreground)">{label}</span>
        <Table head={head.length ? head : ["value"]} rows={records.map((record) => head.map((key) => scalar(record[key])))} />
      </div>
    );
  }
  if (typeof value === "object") {
    if (depth >= 2) {
      return <Row label={label} value={<span className="break-all font-mono">{JSON.stringify(value)}</span>} />;
    }
    return (
      <div className="space-y-1">
        <span className="text-(--iux-muted-foreground)">{label}</span>
        <div className="ml-3 border-l border-(--iux-border) pl-3">
          <GenericEntries data={value as Data} depth={depth + 1} />
        </div>
      </div>
    );
  }
  return <Row label={label} value={scalar(value)} />;
}

function CookieTable({ cookies }: { cookies: unknown }) {
  const rows = asList(cookies)
    .filter((item): item is Data => Boolean(item) && typeof item === "object")
    .map((cookie) => [
      str(cookie.name),
      yesNo(cookie.secure),
      yesNo(cookie.httponly),
      str(cookie.samesite) || "—",
      yesNo(cookie.session),
    ]);
  return <Table head={["Cookie", "Secure", "HttpOnly", "SameSite", "Session"]} rows={rows} />;
}

const WHOIS_ORDER = [
  "domain name", "domain", "registrar", "registrar url", "creation date", "created",
  "updated date", "last updated", "registry expiry date", "expiry date", "expiration date",
  "registrant organization", "registrant country", "name server", "nserver", "dnssec", "status"
];

function WhoisPanel({ data }: { data: Data }) {
  const { available, reason, server, ...fields } = data;
  const keys = Object.keys(fields);
  const ordered = [
    ...WHOIS_ORDER.filter((key) => keys.includes(key)),
    ...keys.filter((key) => !WHOIS_ORDER.includes(key)),
  ];
  return (
    <div className="space-y-2">
      {available === false ? <Row label="Registered" value="no" /> : null}
      {reason ? <Row label="Note" value={str(reason)} /> : null}
      {server ? <Row label="Registry server" value={str(server)} /> : null}
      <GenericEntries data={Object.fromEntries(ordered.map((key) => [key, fields[key]]))} />
    </div>
  );
}

function DnsPanel({ data }: { data: Data }) {
  const { records, addresses, errors, ...rest } = data;
  const recordMap = (records && typeof records === "object" && !Array.isArray(records) ? records : {}) as Data;
  return (
    <div className="space-y-2">
      <SubSection title="Records">
        <Table
          head={["Type", "Values"]}
          rows={Object.entries(recordMap).map(([type, values]) => [type, <Chips key={type} values={asList(values).map(scalar)} />])}
        />
      </SubSection>
      <Row label="Addresses" value={<Chips values={asList(addresses).map(scalar)} />} />
      {errors && typeof errors === "object" && Object.keys(errors as Data).length ? (
        <SubSection title="Lookup errors">
          <GenericEntries data={errors as Data} />
        </SubSection>
      ) : null}
      <GenericEntries data={rest} />
    </div>
  );
}

function CertificatePanel({ data }: { data: Data }) {
  const { sans, unrelated_names, subject, issuer, not_before, not_after, days_left, protocol,
          cipher, bits, serial, fingerprint_sha256, verified, name_count, wildcards, ...rest } = data;
  return (
    <div className="space-y-2">
      <Row label="Subject" value={str(subject)} />
      <Row label="Issuer" value={str(issuer)} />
      <Row label="Validity" value={`${str(not_before)} → ${str(not_after)}${days_left !== undefined ? ` (${str(days_left)} days left)` : ""}`} />
      <Row label="Names" value={<Chips values={asList(sans).map(scalar)} />} />
      {asList(unrelated_names).length ? (
        <Row label="Names outside the target" value={<Chips values={asList(unrelated_names).map(scalar)} />} />
      ) : null}
      <Row label="Connection" value={[protocol, cipher && `${cipher} (${str(bits)} bits)`].filter(Boolean).join(" · ")} />
      <Row label="Chain verified" value={verified === undefined ? "" : yesNo(verified)} />
      <Row label="Serial" value={str(serial)} />
      <Row label="SHA-256 fingerprint" value={<span className="break-all font-mono">{str(fingerprint_sha256)}</span>} />
      {name_count !== undefined ? <Row label="Name count" value={str(name_count)} /> : null}
      {wildcards !== undefined ? <Row label="Wildcard names" value={str(wildcards)} /> : null}
      <GenericEntries data={rest} />
    </div>
  );
}

function HeadersPanel({ data }: { data: Data }) {
  const { score, grade, headers, cookies, tls, https_redirect, waf, checks, ...rest } = data;
  const headerMap = (headers && typeof headers === "object" && !Array.isArray(headers) ? headers : {}) as Data;
  return (
    <div className="space-y-2">
      {score !== undefined ? <Row label="Header score" value={`${str(score)}${grade ? ` (${str(grade)})` : ""}`} /> : null}
      {https_redirect !== undefined ? <Row label="Redirects to https" value={yesNo(https_redirect)} /> : null}
      {waf ? <Row label="WAF" value={str(waf)} /> : null}
      <SubSection title="Security headers">
        <Table head={["Header", "Value"]} rows={Object.entries(headerMap).map(([key, value]) => [key, str(value)])} />
      </SubSection>
      <SubSection title="Cookies">
        <CookieTable cookies={cookies} />
      </SubSection>
      {tls && typeof tls === "object" ? (
        <SubSection title="TLS">
          <GenericEntries data={tls as Data} depth={1} />
        </SubSection>
      ) : null}
      {asList(checks).length ? (
        <SubSection title="Checks behind the findings">
          <Table
            head={["Severity", "Title"]}
            rows={asList(checks).filter((item): item is Data => Boolean(item) && typeof item === "object")
              .map((check) => [str(check.severity), str(check.title)])}
          />
        </SubSection>
      ) : null}
      <GenericEntries data={rest} />
    </div>
  );
}

function CorsPanel({ data }: { data: Data }) {
  const { origin, allow_origin, allow_credentials, reflected, preflight_status,
          preflight_allow_methods, cookies, ...rest } = data;
  return (
    <div className="space-y-2">
      <Row label="Probe origin" value={str(origin)} />
      <Row label="Access-Control-Allow-Origin" value={str(allow_origin) || "absent"} />
      <Row label="Allow-credentials" value={str(allow_credentials) || "absent"} />
      {reflected !== undefined ? <Row label="Origin reflected" value={yesNo(reflected)} /> : null}
      {preflight_status !== undefined ? <Row label="Preflight status" value={str(preflight_status)} /> : null}
      <Row label="Preflight methods" value={str(preflight_allow_methods)} />
      <SubSection title="Cookies"><CookieTable cookies={cookies} /></SubSection>
      <GenericEntries data={rest} />
    </div>
  );
}

function PortPanel({ data }: { data: Data }) {
  const { ports, scanned, cves, cve_lookup, ...rest } = data;
  return (
    <div className="space-y-2">
      <Row label="Ports scanned" value={str(scanned)} />
      {cve_lookup !== undefined ? <Row label="NVD lookup" value={yesNo(cve_lookup)} /> : null}
      <SubSection title="Open or filtered ports">
        <Table
          head={["Port", "Service", "Banner"]}
          rows={asList(ports).filter((item): item is Data => Boolean(item) && typeof item === "object")
            .map((port) => [str(port.port), str(port.service), str(port.banner)])}
        />
      </SubSection>
      {asList(cves).length ? (
        <SubSection title="CVEs matched to open services">
          <Table
            head={["Port", "ID", "Description"]}
            rows={asList(cves).filter((item): item is Data => Boolean(item) && typeof item === "object")
              .map((cve) => [str(cve.port), str(cve.id), str(cve.description)])}
          />
        </SubSection>
      ) : null}
      <GenericEntries data={rest} />
    </div>
  );
}

function SeoPanel({ data }: { data: Data }) {
  const { available, reason, title, title_length, description, description_length, canonical, lang,
          open_graph, twitter_card, robots_meta, headings, images, images_missing_alt,
          internal_links, external_links, words, structured_data_blocks, robots_txt, sitemap, ...rest } = data;
  return (
    <div className="space-y-2">
      {available === false ? <Row label="Note" value={str(reason)} /> : null}
      {title !== undefined ? <Row label="Title" value={`${str(title)} (${str(title_length)} chars)`} /> : null}
      {description !== undefined ? <Row label="Description" value={`${str(description)} (${str(description_length)} chars)`} /> : null}
      <Row label="Canonical" value={str(canonical)} />
      <Row label="Language" value={str(lang)} />
      <Row label="Robots meta" value={str(robots_meta)} />
      <Row label="Images" value={images === undefined ? "" : `${str(images)} (${str(images_missing_alt ?? 0)} without alt text)`} />
      <Row label="Links" value={internal_links === undefined ? "" : `${str(internal_links)} internal · ${str(external_links)} external`} />
      {words !== undefined ? <Row label="Words" value={str(words)} /> : null}
      {structured_data_blocks !== undefined ? <Row label="Structured data blocks" value={str(structured_data_blocks)} /> : null}
      {robots_txt !== undefined ? <Row label="robots.txt" value={yesNo(robots_txt)} /> : null}
      {sitemap !== undefined ? <Row label="Sitemap" value={yesNo(sitemap)} /> : null}
      <Row label="Open Graph" value={<Chips values={asList(open_graph).map(scalar)} />} />
      <Row label="Twitter card" value={<Chips values={asList(twitter_card).map(scalar)} />} />
      {headings && typeof headings === "object" ? (
        <SubSection title="Headings"><GenericEntries data={headings as Data} depth={1} /></SubSection>
      ) : null}
      <GenericEntries data={rest} />
    </div>
  );
}

function TechPanel({ data }: { data: Data }) {
  const { entries, server, powered_by, generator, ...rest } = data;
  return (
    <div className="space-y-2">
      <Row label="Server header" value={str(server)} />
      <Row label="X-Powered-By" value={str(powered_by)} />
      <Row label="Generator meta" value={str(generator)} />
      <SubSection title="Detected technologies">
        <Table
          head={["Technology", "Kind", "Evidence"]}
          rows={asList(entries).filter((item): item is Data => Boolean(item) && typeof item === "object")
            .map((entry) => [str(entry.name), str(entry.kind), str(entry.evidence)])}
        />
      </SubSection>
      <GenericEntries data={rest} />
    </div>
  );
}

function GenericPanel({ data }: { data: Data }) {
  return <GenericEntries data={data} />;
}

const records = (value: unknown): Data[] =>
  asList(value).filter((item): item is Data => Boolean(item) && typeof item === "object" && !Array.isArray(item));

function Note({ data }: { data: Data }) {
  if (data.available !== false) return null;
  return <Row label="Note" value={str(data.reason)} />;
}

function ContactPanel({ data }: { data: Data }) {
  const { available, reason, pages_crawled, pages, emails, phones, socials, ...rest } = data;
  return (
    <div className="space-y-2">
      <Note data={{ available, reason }} />
      <Row label="Pages crawled" value={str(pages_crawled)} />
      {records(emails).length ? (
        <SubSection title="Email addresses">
          <Table head={["Address", "Found on"]} rows={records(emails).map((item) => [str(item.address), str(item.found_on)])} />
        </SubSection>
      ) : null}
      {records(phones).length ? (
        <SubSection title="Phone numbers">
          <Table head={["Number", "Found on"]} rows={records(phones).map((item) => [str(item.number), str(item.found_on)])} />
        </SubSection>
      ) : null}
      {records(socials).length ? (
        <SubSection title="Social profiles">
          <Table head={["Network", "Link"]} rows={records(socials).map((item) => [str(item.network), str(item.url)])} />
        </SubSection>
      ) : null}
      {asList(pages).length ? <Row label="Pages" value={<Chips values={asList(pages).map(str)} />} /> : null}
      <GenericEntries data={rest} />
    </div>
  );
}

function SubdomainPanel({ data }: { data: Data }) {
  const { available, reason, count, names, interesting, source, ...rest } = data;
  const flagged = new Set(asList(interesting).map(str));
  return (
    <div className="space-y-2">
      <Note data={{ available, reason }} />
      <Row label="Names found" value={count === undefined ? "" : `${str(count)} · ${str(source)}`} />
      {flagged.size ? <Row label="Worth a look" value={<Chips values={[...flagged]} />} /> : null}
      {asList(names).length ? (
        <SubSection title="Certificate-transparency names">
          <div className="max-h-48 overflow-y-auto">
            <Chips values={asList(names).map(str).filter((name) => !flagged.has(name))} />
          </div>
        </SubSection>
      ) : null}
      <GenericEntries data={rest} />
    </div>
  );
}

function ContentPanel({ data }: { data: Data }) {
  const { available, reason, scripts_scanned, bytes_scanned, secrets, taint, source_maps, exposed_source_maps,
          framework_data, ...rest } = data;
  const framework = (framework_data && typeof framework_data === "object" ? framework_data : {}) as Data;
  return (
    <div className="space-y-2">
      <Note data={{ available, reason }} />
      <Row label="Scanned" value={scripts_scanned === undefined ? "" : `${str(scripts_scanned)} scripts · ${str(bytes_scanned)} bytes`} />
      <SubSection title="Secrets (masked)">
        {records(secrets).length ? (
          <Table head={["Kind", "Severity", "Count", "Samples", "Where"]}
            rows={records(secrets).map((item) => [str(item.kind), str(item.severity), str(item.count),
              asList(item.samples).map(str).join(", "), asList(item.where).map(str).join(", ")])} />
        ) : <p className="text-(--iux-muted-foreground)">None found</p>}
      </SubSection>
      {records(taint).length ? (
        <SubSection title="DOM-XSS candidates">
          <Table head={["Where", "Variable", "Sink", "Lines", "Code"]}
            rows={records(taint).map((item) => [str(item.where), str(item.variable), str(item.sink),
              `${str(item.source_line)} → ${str(item.line)}`, <code key="code" className="break-all">{str(item.code)}</code>])} />
        </SubSection>
      ) : null}
      {asList(source_maps).length ? <Row label="Source maps referenced" value={<Chips values={asList(source_maps).map(str)} />} /> : null}
      {asList(exposed_source_maps).length ? <Row label="Source maps readable" value={<Chips values={asList(exposed_source_maps).map(str)} />} /> : null}
      {framework.next_data !== undefined ? <Row label="__NEXT_DATA__ blob" value={yesNo(framework.next_data)} /> : null}
      <GenericEntries data={rest} />
    </div>
  );
}

function TakeoverPanel({ data }: { data: Data }) {
  const { checked, dangling, confirmed, candidates, services, ...rest } = data;
  const chain = (item: Data) => asList(item.chain).map(str).join(" → ");
  return (
    <div className="space-y-2">
      <Row label="Names checked" value={candidates === undefined ? "" : `${str(candidates)} · ${str(services)} service fingerprints`} />
      {records(confirmed).length ? (
        <SubSection title="Takeover page matched">
          <Table head={["Name", "Service", "CNAME chain", "Evidence"]}
            rows={records(confirmed).map((item) => [str(item.name), str(item.service), chain(item), str(item.evidence)])} />
        </SubSection>
      ) : null}
      {records(dangling).length ? (
        <SubSection title="Dangling CNAMEs">
          <Table head={["Name", "Service", "CNAME chain", "Evidence"]}
            rows={records(dangling).map((item) => [str(item.name), str(item.service), chain(item), str(item.evidence)])} />
        </SubSection>
      ) : null}
      {records(checked).length ? (
        <SubSection title="Checked names">
          <Table head={["Name", "Service", "CNAME chain"]}
            rows={records(checked).map((item) => [str(item.name), str(item.service || item.error), chain(item)])} />
        </SubSection>
      ) : null}
      <GenericEntries data={rest} />
    </div>
  );
}

function OriginPanel({ data }: { data: Data }) {
  const { cdn, candidates, exposed, note, ...rest } = data;
  const open = new Set(records(exposed).map((item) => str(item.name)));
  return (
    <div className="space-y-2">
      <Row label="CDN in front" value={str(cdn) || "none detected"} />
      {records(candidates).length ? (
        <SubSection title="Names under the target">
          <Table head={["Name", "Addresses", "Edge", "HTTP", "Origin candidate"]}
            rows={records(candidates).map((item) => [str(item.name), asList(item.addresses).map(str).join(", "),
              str(item.edge) || "—", str(item.status) || "—", open.has(str(item.name)) ? "yes" : "no"])} />
        </SubSection>
      ) : null}
      <Row label="Note" value={str(note)} />
      <GenericEntries data={rest} />
    </div>
  );
}

function FrameworkPanel({ data }: { data: Data }) {
  const { available, reason, development_build, next_data, next_data_parsed, sensitive_keys, ...rest } = data;
  return (
    <div className="space-y-2">
      <Note data={{ available, reason }} />
      {development_build !== undefined ? <Row label="Development build served" value={yesNo(development_build)} /> : null}
      {next_data !== undefined ? <Row label="__NEXT_DATA__ blob" value={yesNo(next_data)} /> : null}
      {next_data_parsed !== undefined ? <Row label="Blob parses as JSON" value={yesNo(next_data_parsed)} /> : null}
      {asList(sensitive_keys).length ? <Row label="Sensitive-looking keys" value={<Chips values={asList(sensitive_keys).map(str)} />} /> : null}
      <GenericEntries data={rest} />
    </div>
  );
}

const PANELS: Record<string, ComponentType<{ data: Data }>> = {
  domain_info: WhoisPanel,
  dns_records: DnsPanel,
  ssl_san: CertificatePanel,
  security_analysis: HeadersPanel,
  cookies_cors: CorsPanel,
  port_exposure: PortPanel,
  seo_analysis: SeoPanel,
  web_technologies: TechPanel,
  contact_spy: ContactPanel,
  subdomain_discovery: SubdomainPanel,
  content_scan: ContentPanel,
  subdomain_takeover: TakeoverPanel,
  origin_exposure: OriginPanel,
  react_exposure: FrameworkPanel,
};

export const hasData = (module: WebSecModuleOutcome): boolean =>
  Boolean(module.data && Object.keys(module.data).length > 0);

export function ModulePanel({ module }: { module: WebSecModuleOutcome }) {
  const data = module.data;
  if (!data || !Object.keys(data).length) return null;
  const Panel = PANELS[module.id] ?? GenericPanel;
  return (
    <div
      role="region"
      aria-label={`${module.label} details`}
      className="space-y-2 rounded border border-(--iux-border) bg-(--iux-bg) p-3 text-xs"
    >
      <Panel data={data} />
    </div>
  );
}
