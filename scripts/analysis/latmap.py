#!/usr/bin/env python3
"""PENT-19: Analysis session brain-map (lat.md) generator and graph validator."""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore[assignment]

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
SLUG_RE = re.compile(r"[^a-z0-9]+")
ANSI_ESCAPE_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences
    r"|\x1b[PX^_].*?\x1b\\"  # DCS, SOS, PM, APC sequences
    r"|\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"  # 7-bit CSI sequences
    r"|\x9b[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"  # 8-bit CSI sequences
    r"|\x1b[@-Z\\-_]"  # 2-byte ESC sequences
)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
REVISION_FRONTMATTER_RE = re.compile(r"^revision:\s*(\d+)\s*$", re.MULTILINE)


def sanitize_text(value: Any) -> str:
    """Strip all ANSI/VT escape sequences and control characters from text."""
    if value is None:
        return ""
    cleaned = ANSI_ESCAPE_RE.sub("", str(value))
    cleaned = CONTROL_CHAR_RE.sub("", cleaned)
    return " ".join(cleaned.split()).strip()


def escape_markdown(value: str) -> str:
    """Escape raw HTML so generated Markdown cannot execute active markup."""
    return html.escape(sanitize_text(value), quote=False)


def slugify(value: Any) -> str:
    """Convert an arbitrary identifier into a stable lowercase anchor slug."""
    cleaned = sanitize_text(value).lower()
    return SLUG_RE.sub("-", cleaned).strip("-")


def _require_list(value: Any, field_name: str) -> list[Any]:
    """Validate that a list-valued field is actually a JSON array (not a string)."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"Field '{field_name}' must be a list, got {type(value).__name__}.")
    return value


def _dedupe_slugs(values: list[Any], field_name: str) -> list[str]:
    """Slugify and deduplicate a list of string references while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for entry in values:
        if not isinstance(entry, str):
            raise ValueError(f"Entries in '{field_name}' must be strings.")
        slug = slugify(entry)
        if not slug:
            raise ValueError(f"Empty or invalid identifier in '{field_name}'.")
        if slug not in seen:
            seen.add(slug)
            result.append(slug)
    return result


def build_demo_session() -> dict[str, Any]:
    """Return a realistic built-in demo session for PENT-19 verification."""
    return {
        "session_id": "avelium-pentest-session-01",
        "revision": 1,
        "title": "Avelium DMZ WAF & Android Lab Brain-Map",
        "doc_path": "lat.md/session-brain-map.md",
        "targets": [
            {
                "id": "avelium-dmz-waf",
                "name": "Avelium DMZ WAF Reverse Proxy",
                "host": "10.64.60.5",
                "scope": "in-scope",
                "tags": ["dmz", "waf", "nginx"],
                "notes": "Authorized lab DMZ reverse proxy fronting LMS backend.",
            },
            {
                "id": "avelium-hq-vpn",
                "name": "Avelium HQ WireGuard Gateway",
                "host": "10.64.10.1",
                "scope": "in-scope",
                "tags": ["vpn", "firewall"],
                "notes": "Authorized lab VPN gateway enforcing MFA SSH access.",
            },
        ],
        "scripts": [
            {
                "id": "waf-crs-probe",
                "name": "OWASP CRS SQLi Probe",
                "path": "scripts/analysis/waf_crs_probe.py",
                "targets": ["avelium-dmz-waf", "avelium-hq-vpn"],
                "purpose": "Verifies SQL injection blocking and direct backend isolation.",
            }
        ],
        "findings": [
            {
                "id": "waf-sqli-blocked",
                "title": "SQLi Payload Blocked at WAF Edge",
                "severity": "info",
                "target": "avelium-dmz-waf",
                "script": "waf-crs-probe",
                "evidence": "Payload `' OR 1=1 --` returned HTTP 403 Forbidden at 10.64.60.5.",
                "remediation": "Maintain OWASP CRS paranoia level 2 and forward WAF alerts to SIEM.",
            },
            {
                "id": "direct-backend-bypass-prevented",
                "title": "Direct Backend Access Locked to WAF Source IP",
                "severity": "low",
                "target": "avelium-hq-vpn",
                "script": "waf-crs-probe",
                "evidence": "Forward chain drops traffic to 10.64.60.10 unless source is 10.64.60.5.",
                "remediation": "Keep default-deny rules on input, forward, and output chains.",
            },
        ],
    }


def normalize_session(raw: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize raw session JSON without silently dropping records."""
    if not isinstance(raw, dict):
        raise ValueError("Session root must be a JSON object.")

    session_id = sanitize_text(raw.get("session_id") or "analysis-session")
    title = sanitize_text(raw.get("title") or session_id)
    doc_path = sanitize_text(raw.get("doc_path") or "lat.md/session-brain-map.md")

    revision_raw = raw.get("revision")
    revision: int | None = None
    if revision_raw is not None:
        if isinstance(revision_raw, bool) or not isinstance(revision_raw, int) or revision_raw < 0:
            raise ValueError("Field 'revision' must be a non-negative integer.")
        revision = revision_raw

    seen_ids: set[str] = set()

    targets: list[dict[str, Any]] = []
    for idx, item in enumerate(_require_list(raw.get("targets"), "targets")):
        if not isinstance(item, dict):
            raise ValueError(f"targets[{idx}] must be an object.")
        tid = slugify(item.get("id") or item.get("name") or item.get("host") or "")
        if not tid:
            raise ValueError(f"targets[{idx}] is missing a usable identifier (id/name/host).")
        if tid in seen_ids:
            raise ValueError(f"Duplicate or colliding node ID '{tid}' at targets[{idx}].")
        seen_ids.add(tid)

        raw_tags = _require_list(item.get("tags"), f"targets[{idx}].tags")
        targets.append(
            {
                "id": tid,
                "kind": "target",
                "name": sanitize_text(item.get("name") or tid),
                "host": sanitize_text(item.get("host") or "unknown-host"),
                "scope": sanitize_text(item.get("scope") or "unverified"),
                "tags": _dedupe_slugs(raw_tags, f"targets[{idx}].tags"),
                "notes": sanitize_text(
                    item.get("notes") or "Authorization and scope not verified in session."
                ),
            }
        )

    scripts: list[dict[str, Any]] = []
    for idx, item in enumerate(_require_list(raw.get("scripts"), "scripts")):
        if not isinstance(item, dict):
            raise ValueError(f"scripts[{idx}] must be an object.")
        sid = slugify(item.get("id") or item.get("name") or item.get("path") or "")
        if not sid:
            raise ValueError(f"scripts[{idx}] is missing a usable identifier (id/name/path).")
        if sid in seen_ids:
            raise ValueError(f"Duplicate or colliding node ID '{sid}' at scripts[{idx}].")
        seen_ids.add(sid)

        raw_targets = _require_list(item.get("targets"), f"scripts[{idx}].targets")
        scripts.append(
            {
                "id": sid,
                "kind": "script",
                "name": sanitize_text(item.get("name") or sid),
                "path": sanitize_text(item.get("path") or f"scripts/analysis/{sid}.py"),
                "targets": _dedupe_slugs(raw_targets, f"scripts[{idx}].targets"),
                "purpose": sanitize_text(item.get("purpose") or "Automated inspection script."),
            }
        )

    findings: list[dict[str, Any]] = []
    for idx, item in enumerate(_require_list(raw.get("findings"), "findings")):
        if not isinstance(item, dict):
            raise ValueError(f"findings[{idx}] must be an object.")
        fid = slugify(item.get("id") or item.get("title") or "")
        if not fid:
            raise ValueError(f"findings[{idx}] is missing a usable identifier (id/title).")
        if fid in seen_ids:
            raise ValueError(f"Duplicate or colliding node ID '{fid}' at findings[{idx}].")
        seen_ids.add(fid)

        sev = sanitize_text(item.get("severity") or "info").lower()
        if sev not in VALID_SEVERITIES:
            sev = "info"

        target_ref = slugify(item.get("target") or "")
        script_ref = slugify(item.get("script") or "")
        findings.append(
            {
                "id": fid,
                "kind": "finding",
                "title": sanitize_text(item.get("title") or fid),
                "severity": sev,
                "target": target_ref,
                "script": script_ref,
                "evidence": sanitize_text(item.get("evidence") or "Verified during session."),
                "remediation": sanitize_text(
                    item.get("remediation") or "Apply least-privilege control."
                ),
            }
        )

    return {
        "session_id": session_id,
        "revision": revision,
        "title": title,
        "doc_path": doc_path,
        "targets": targets,
        "scripts": scripts,
        "findings": findings,
    }


def validate_graph(session: dict[str, Any]) -> dict[str, Any]:
    """Validate links across targets, scripts, and findings."""
    known_targets = {t["id"] for t in session["targets"]}
    known_scripts = {s["id"] for s in session["scripts"]}
    known_findings = {f["id"] for f in session["findings"]}
    all_nodes = known_targets | known_scripts | known_findings

    edges: list[dict[str, str]] = []
    dangling_links: list[dict[str, str]] = []
    connected_nodes: set[str] = set()

    for s in session["scripts"]:
        for tid in s["targets"]:
            if tid in known_targets:
                edges.append({"from": s["id"], "to": tid, "type": "inspects"})
                connected_nodes.update((s["id"], tid))
            else:
                dangling_links.append(
                    {"source": s["id"], "missing_target": tid, "field": "targets"}
                )

    for f in session["findings"]:
        if f["target"]:
            if f["target"] in known_targets:
                edges.append({"from": f["id"], "to": f["target"], "type": "affects"})
                connected_nodes.update((f["id"], f["target"]))
            else:
                dangling_links.append(
                    {"source": f["id"], "missing_target": f["target"], "field": "target"}
                )
        if f["script"]:
            if f["script"] in known_scripts:
                edges.append({"from": f["id"], "to": f["script"], "type": "detected_by"})
                connected_nodes.update((f["id"], f["script"]))
            else:
                dangling_links.append(
                    {"source": f["id"], "missing_target": f["script"], "field": "script"}
                )

    orphan_nodes = sorted(all_nodes - connected_nodes)
    severity_counts = {sev: 0 for sev in VALID_SEVERITIES}
    for f in session["findings"]:
        severity_counts[f["severity"]] += 1

    if dangling_links:
        status = "FAIL"
    elif orphan_nodes:
        status = "WARN"
    else:
        status = "OK"

    return {
        "status": status,
        "session_id": session["session_id"],
        "counts": {
            "targets": len(known_targets),
            "scripts": len(known_scripts),
            "findings": len(known_findings),
            "total_nodes": len(all_nodes),
            "edges": len(edges),
        },
        "severities": severity_counts,
        "edges": edges,
        "dangling_links": dangling_links,
        "orphan_nodes": orphan_nodes,
    }


def render_lat_markdown(session: dict[str, Any], report: dict[str, Any]) -> str:
    """Render a lat.md-compatible Markdown document with working [[wiki-links]]."""
    doc_path = session["doc_path"]

    def wiki_link(node_id: str, label: str | None = None) -> str:
        target_ref = f"{doc_path}#{node_id}"
        return f"[[{target_ref}|{label}]]" if label else f"[[{target_ref}]]"

    lines = [
        "---",
        f"id: {json.dumps(session['session_id'])}",
        "type: analysis-brain-map",
        "generator: scripts/analysis/latmap.py",
    ]
    if session.get("revision") is not None:
        lines.append(f"revision: {session['revision']}")
    lines.extend(
        [
            "---",
            "",
            f"# {escape_markdown(session['title'])}",
            "",
            (
                f"Session brain-map (`{escape_markdown(session['session_id'])}`) generated by "
                f"`scripts/analysis/latmap.py` with **{report['counts']['total_nodes']} nodes** "
                f"and **{report['counts']['edges']} links** (Status: **{report['status']}**)."
            ),
            "",
            "## Targets",
            "",
        ]
    )

    if not session["targets"]:
        lines.extend(["No targets recorded in this session.", ""])
    else:
        for t in session["targets"]:
            related_scripts = [
                wiki_link(s["id"], s["id"]) for s in session["scripts"] if t["id"] in s["targets"]
            ]
            related_findings = [
                wiki_link(f["id"], f["id"]) for f in session["findings"] if f["target"] == t["id"]
            ]
            lines.extend(
                [
                    f"### {t['id']}",
                    "",
                    (
                        f"{escape_markdown(t['name'])} (`{escape_markdown(t['host'])}`, "
                        f"scope: `{escape_markdown(t['scope'])}`). {escape_markdown(t['notes'])}"
                    ),
                    "",
                    f"- Inspected by scripts: {', '.join(related_scripts) if related_scripts else 'none'}",
                    f"- Reported findings: {', '.join(related_findings) if related_findings else 'none'}",
                    "",
                ]
            )

    lines.extend(["## Scripts", ""])
    if not session["scripts"]:
        lines.extend(["No scripts recorded in this session.", ""])
    else:
        known_target_ids = {t["id"] for t in session["targets"]}
        for s in session["scripts"]:
            t_links = [
                wiki_link(tid, tid) for tid in s["targets"] if tid in known_target_ids
            ]
            f_links = [
                wiki_link(f["id"], f["id"]) for f in session["findings"] if f["script"] == s["id"]
            ]
            lines.extend(
                [
                    f"### {s['id']}",
                    "",
                    (
                        f"{escape_markdown(s['name'])} (`{escape_markdown(s['path'])}`). "
                        f"{escape_markdown(s['purpose'])}"
                    ),
                    "",
                    f"- Evaluates targets: {', '.join(t_links) if t_links else 'none'}",
                    f"- Produces findings: {', '.join(f_links) if f_links else 'none'}",
                    "",
                ]
            )

    lines.extend(["## Findings", ""])
    if not session["findings"]:
        lines.extend(["No security findings recorded in this session.", ""])
    else:
        known_target_ids = {t["id"] for t in session["targets"]}
        known_script_ids = {s["id"] for s in session["scripts"]}
        for f in session["findings"]:
            t_link = (
                wiki_link(f["target"], f["target"])
                if f["target"] in known_target_ids
                else f"`{escape_markdown(f['target'] or 'unlinked')}`"
            )
            s_link = (
                wiki_link(f["script"], f["script"])
                if f["script"] in known_script_ids
                else f"`{escape_markdown(f['script'] or 'manual')}`"
            )
            lines.extend(
                [
                    f"### {f['id']}",
                    "",
                    (
                        f"[{f['severity'].upper()}] {escape_markdown(f['title'])} "
                        f"affecting {t_link} (detected via {s_link})."
                    ),
                    "",
                    f"- Evidence: {escape_markdown(f['evidence'])}",
                    f"- Remediation: {escape_markdown(f['remediation'])}",
                    "",
                ]
            )

    return "\n".join(lines).rstrip() + "\n"


def _read_existing_revision(path: Path) -> int | None:
    if not path.exists():
        return None
    head = path.read_text(encoding="utf-8", errors="ignore")[:512]
    match = REVISION_FRONTMATTER_RE.search(head)
    return int(match.group(1)) if match else None


def atomic_write_text(path: Path, content: str, revision: int | None = None) -> None:
    """Serialize writers with a lock file, enforce revision monotonicity, and write atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.parent / f".{path.name}.lock"

    with open(lock_path, "a+", encoding="utf-8") as lock_file:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            if revision is not None:
                existing_rev = _read_existing_revision(path)
                if existing_rev is not None and revision < existing_rev:
                    raise ValueError(
                        f"Refusing to overwrite newer map revision {existing_rev} with older revision {revision}."
                    )
            fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", text=True)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(content)
                os.replace(tmp_name, path)
            except Exception:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
                raise
        finally:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _resolve_doc_path_for_output(output_path: Path) -> str:
    try:
        return output_path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return output_path.as_posix()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate and validate a lat.md-compatible analysis session brain-map."
    )
    parser.add_argument("--session", type=Path, help="Path to input session JSON file.")
    parser.add_argument("--demo", action="store_true", help="Run with the built-in demo session.")
    parser.add_argument("--output", type=Path, help="Write generated Markdown to this file.")
    parser.add_argument("--json", action="store_true", help="Print structured JSON output.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Return exit code 1 when validation status is FAIL.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 1 on FAIL or WARN (implies --check).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.session and args.output:
        if args.session.resolve() == args.output.resolve():
            print("[FAIL] --output cannot point to the same file as --session.", file=sys.stderr)
            return 1

    try:
        if args.session:
            raw_data = json.loads(args.session.read_text(encoding="utf-8"))
        elif args.demo:
            raw_data = build_demo_session()
        else:
            parser.error("Provide either --session <path.json> or --demo.")
            return 2
        session = normalize_session(raw_data)
        if args.output:
            session["doc_path"] = _resolve_doc_path_for_output(args.output)
    except Exception as exc:
        print(f"[FAIL] Could not load session: {exc}", file=sys.stderr)
        return 1

    report = validate_graph(session)
    markdown = render_lat_markdown(session, report)

    if args.output:
        try:
            atomic_write_text(args.output, markdown, revision=session.get("revision"))
        except Exception as exc:
            print(f"[FAIL] Could not write output: {exc}", file=sys.stderr)
            return 1

    if args.json:
        print(json.dumps({"session": session, "validation": report, "markdown": markdown}, indent=2))
    else:
        print(markdown, end="")

    if args.check or args.strict:
        if report["status"] == "FAIL":
            return 1
        if args.strict and report["status"] == "WARN":
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
