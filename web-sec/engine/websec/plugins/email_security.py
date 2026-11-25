"""SPF, DMARC, DKIM and MTA-STS (upstream plugin ``Email Security``)."""
from __future__ import annotations

from typing import Dict, List

from ..models import Finding
from ..net.dns import DnsError
from ..registry import module

SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "mail")


@module("email_security", label="Email authentication",
        description="SPF, DMARC policy, DKIM selectors, MTA-STS and BIMI",
        group="posture", weight="light", order=230)
def email_security(ctx):
    def txt(name):
        try:
            return [str(value) for value in ctx.dns.values(name, "TXT")]
        except DnsError:
            return []

    spf_records = [record for record in txt(ctx.target) if record.lower().startswith("v=spf1")]
    spf = spf_records[0] if spf_records else ""
    dmarc_records = [record for record in txt(f"_dmarc.{ctx.target}") if "v=dmarc1" in record.lower()]
    dmarc = dmarc_records[0] if dmarc_records else ""
    policy = ""
    for part in dmarc.split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "p":
            policy = value.strip().lower()
    selectors: Dict[str, bool] = {}
    for selector in SELECTORS:
        selectors[selector] = any("v=dkim1" in record.lower()
                                  for record in txt(f"{selector}._domainkey.{ctx.target}"))
    mta_sts = any("v=stsp" in record.lower() for record in txt(f"_mta-sts.{ctx.target}"))
    bimi = any("v=bimi1" in record.lower() for record in txt(f"default._bimi.{ctx.target}"))
    data = {"spf": spf[:500], "spf_records": len(spf_records), "dmarc": dmarc[:500],
            "dmarc_policy": policy, "dkim_selectors": selectors,
            "mta_sts": mta_sts, "bimi": bimi}
    findings: List[Finding] = []
    if not spf:
        findings.append(Finding(module="email_security", severity="medium", kind="spf-missing",
                                title="No SPF record is published",
                                detail="Receivers cannot tell which hosts may send mail for the domain.",
                                remediation="Publish v=spf1 with only the sending hosts and end in -all."))
    else:
        lowered = spf.lower()
        if "+all" in lowered or " ?all" in lowered:
            findings.append(Finding(module="email_security", severity="high", kind="spf-all",
                                    title="SPF allows every sender",
                                    detail="The policy ends in +all or ?all.",
                                    remediation="End the record in -all and list only real senders."))
        if len(spf_records) > 1:
            findings.append(Finding(module="email_security", severity="medium", kind="spf-multiple",
                                    title="More than one SPF record is published",
                                    detail=f"{len(spf_records)} records; receivers treat this as a permanent error.",
                                    remediation="Merge them into one record."))
    if not dmarc:
        findings.append(Finding(module="email_security", severity="high", kind="dmarc-missing",
                                title="No DMARC record is published",
                                detail="Anyone can spoof the domain in the From header.",
                                remediation="Publish _dmarc TXT starting with p=none, then move to quarantine and reject."))
    elif policy == "none":
        findings.append(Finding(module="email_security", severity="medium", kind="dmarc-none",
                                title="DMARC only monitors",
                                detail="p=none asks receivers to report but not to block.",
                                remediation="Move to p=quarantine, then p=reject, once reports are clean."))
    if not any(selectors.values()):
        findings.append(Finding(module="email_security", severity="info", kind="dkim-unknown",
                                title="No DKIM key was found at the common selectors",
                                detail="Selectors are not enumerable; this is not proof that DKIM is absent.",
                                remediation="Confirm the selector with the mail provider and publish the key."))
    if not mta_sts:
        findings.append(Finding(module="email_security", severity="info", kind="mta-sts-missing",
                                title="MTA-STS is not published",
                                detail="Opportunistic TLS can be downgraded by an active attacker.",
                                remediation="Publish an MTA-STS policy and a _mta-sts TXT record."))
    return data, findings
