/**
 * Public /labs/websec/ page: what the lab does, where its boundary sits, and
 * live readiness from the same console endpoint the workbench uses. Actions and
 * plans stay on the generic lab page; this one is read-only.
 */
import { useEffect, useState } from "react";
import { ShieldCheckIcon } from "@phosphor-icons/react";
import { AppShell } from "../../shell/app-shell";
import { Badge, PageHead, Section, Skeleton } from "../../components/ui";
import { api, type WebSecStatus } from "../../lib/api";

const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error));

export default function WebSecPublicPage() {
  const [status, setStatus] = useState<WebSecStatus | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      api.websecStatus().then((value) => {
        if (cancelled) return;
        setStatus(value);
        setError("");
      }).catch((reason) => {
        if (!cancelled) setError(errorText(reason));
      });
    };
    load();
    const timer = window.setInterval(load, 15000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const ready = status?.state === "ready";
  const tone = ready ? "success" : status?.state === "needs-setup" ? "warning" : "danger";
  const stateText = ready ? "Ready" : status?.state === "needs-setup" ? "Needs setup" : "Unavailable";

  return (
    <AppShell activeId="web-sec">
      <main className="space-y-6">
        <PageHead
          icon={<ShieldCheckIcon size={22} />}
          title="Web Sec Lab"
          description="Scope-guarded web posture assessment"
          actions={status ? <Badge tone={tone}>{stateText}</Badge> : null}
        />

        {error ? (
          <p role="alert" className="rounded-md border border-(--iux-danger) px-3 py-2 text-sm text-(--iux-danger)">
            {error}
          </p>
        ) : null}

        <Section title="Readiness" description={status?.notes?.[0] ?? ""}>
          {status ? (
            <div className="space-y-3 text-sm">
              {status.reasons.length ? (
                <ul className="list-disc space-y-1 pl-5 text-(--iux-muted-foreground)">
                  {status.reasons.map((reason) => <li key={reason}>{reason}</li>)}
                </ul>
              ) : null}
              <ul className="space-y-2">
                {status.requirements.map((requirement) => (
                  <li key={requirement.id} className="flex flex-wrap items-center gap-2">
                    <Badge tone={requirement.found ? "success" : requirement.required ? "danger" : "warning"}>
                      {requirement.found ? "found" : requirement.required ? "Needs setup" : "optional"}
                    </Badge>
                    <span>{requirement.label}</span>
                    {requirement.hint ? (
                      <span className="text-xs text-(--iux-muted-foreground)">{requirement.hint}</span>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <Skeleton />
          )}
        </Section>

        <Section title="Boundaries" description="">
          <ul className="list-disc space-y-1 pl-5 text-sm text-(--iux-muted-foreground)">
            <li>Assesses one authorized host and grades its posture.</li>
            <li>Read-only by default; intrusive checks need --active and written authorization.</li>
            <li>Public data comes only from crt.sh, the Wayback CDX API and NVD.</li>
          </ul>
          <a className="mt-3 inline-flex items-center gap-1 text-sm underline" href="/web-sec/">
            Open the workbench
          </a>
        </Section>
      </main>
    </AppShell>
  );
}
