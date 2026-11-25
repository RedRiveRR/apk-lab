"""Command line for the Web Sec Lab: status, doctor, scan, bulk, reports."""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from . import report as report_module
from .config import Options, default_storage, ensure_storage
from .history import History, slug
from .registry import catalogue, plugin_report
from .runner import run_scan
from .scope import Guard, ScopeRefused, describe
from .version import VERSION

MAX_BULK = 50
_GRADE_EXIT = {"A": 0, "B": 0, "C": 1, "D": 2, "F": 3}


def _grade_exit(grade: str) -> int:
    """Worst-grade exit code: 0 through B passes, 1 C, 2 D, 3 F; errors stay 3."""
    return _GRADE_EXIT.get(str(grade or "")[:1].upper(), 3)


def diff_reports(current: Dict[str, object], previous: Dict[str, object]) -> Dict[str, object]:
    """What changed between two reports of the same target.

    Findings match on module and kind (falling back to the title), so a wording
    change does not turn a standing finding into a new one.
    """
    def index(findings) -> Dict[str, Dict[str, object]]:
        return {f"{f.get('module')}|{f.get('kind') or f.get('title')}": f for f in (findings or [])}

    now, before = index(current.get("findings")), index(previous.get("findings"))
    current_summary = current.get("summary") or {}
    previous_summary = previous.get("summary") or {}
    previous_modules = {m.get("id"): m.get("status") for m in (previous.get("modules") or [])}
    module_changes = [
        {"id": m.get("id"), "previous": previous_modules.get(m.get("id")), "current": m.get("status")}
        for m in (current.get("modules") or [])
        if previous_modules.get(m.get("id")) not in (None, m.get("status"))
    ]

    def brief(finding: Dict[str, object]) -> Dict[str, object]:
        return {"module": finding.get("module"), "severity": finding.get("severity"),
                "title": finding.get("title")}

    score_now = int(current.get("score") or 0)
    score_before = int(previous.get("score") or 0)
    return {
        "target": current.get("target"),
        "score": {"current": score_now, "previous": score_before, "delta": score_now - score_before},
        "grade": {"current": current.get("grade"), "previous": previous.get("grade")},
        "summary": {
            str(severity): {"current": int(current_summary.get(severity, 0) or 0),
                            "previous": int(previous_summary.get(severity, 0) or 0)}
            for severity in ("critical", "high", "medium", "low", "info", "total")
        },
        "new": sorted((brief(f) for key, f in now.items() if key not in before),
                      key=lambda item: (str(item["module"]), str(item["title"]))),
        "resolved": sorted((brief(f) for key, f in before.items() if key not in now),
                           key=lambda item: (str(item["module"]), str(item["title"]))),
        "modules": module_changes,
    }


def _render_diff(diff: Dict[str, object]) -> str:
    lines = [
        f"{diff['target']}: grade {diff['grade']['previous']} → {diff['grade']['current']} "
        f"({diff['score']['previous']} → {diff['score']['current']}, {diff['score']['delta']:+d})",
    ]
    for key, label in (("new", "new findings"), ("resolved", "resolved findings")):
        entries = diff[key]
        lines.append(f"{label}: {len(entries)}")
        for item in entries:
            lines.append(f"  [{item['severity']}] {item['module']}: {item['title']}")
    for change in diff["modules"]:
        lines.append(f"module {change['id']}: {change['previous']} → {change['current']}")
    return "\n".join(lines) + "\n"


def _load_catalogue() -> List[Dict[str, object]]:
    from .catalog import ensure_loaded
    ensure_loaded()
    return catalogue()


def _print(value: str) -> None:
    sys.stdout.write(value if value.endswith("\n") else value + "\n")


def _error(message: str) -> None:
    sys.stderr.write(message if message.endswith("\n") else message + "\n")


def status(as_json: bool = False) -> int:
    modules = _load_catalogue()
    storage = default_storage()
    guard_status = Guard().status()
    payload = {
        "version": VERSION,
        "python": sys.version.split()[0],
        "storage": storage,
        "storage_writable": os.access(storage if os.path.isdir(storage) else os.path.dirname(storage), os.W_OK),
        "scope": guard_status,
        "modules": len(modules),
        "plugins": len([entry for entry in plugin_report()["loaded"]]),
        "ready": bool(guard_status.get("valid")),
    }
    if as_json:
        _print(json.dumps(payload, indent=2))
        return 0
    _print(f"Web Sec Lab {VERSION} on Python {payload['python']}")
    _print(f"modules   {payload['modules']} ({payload['plugins']} from plugins)")
    _print(f"storage   {payload['storage']}")
    if guard_status.get("valid"):
        _print(f"scope     {guard_status.get('name', '(unnamed)')} · "
               f"{guard_status.get('hosts', 0)} host rule(s) · expires {guard_status.get('expires') or 'never'}")
        _print("state     ready")
    else:
        _print(f"scope     not usable: {guard_status.get('reason', 'no scope declared')}")
        _print("state     needs-setup — declare a scope with console/scope.example.json")
    return 0


def doctor(as_json: bool = False) -> int:
    checks: List[Dict[str, object]] = []

    def check(name: str, ok: bool, detail: str, required: bool = True) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail, "required": required})

    check("python", sys.version_info >= (3, 9), f"{sys.version.split()[0]} (needs 3.9+)")
    check("engine", True, f"Web Sec Lab {VERSION}")
    storage = default_storage()
    try:
        ensure_storage(storage)
        probe = os.path.join(storage, ".doctor")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.remove(probe)
        check("storage", True, f"{storage} is writable")
    except OSError as exc:
        check("storage", False, f"{storage}: {exc}")
    guard_info = describe()
    guard_status = Guard().status()
    check("scope", bool(guard_status.get("valid")),
          "the declared scope is valid" if guard_status.get("valid")
          else str(guard_status.get("reason", "no scope declared")))
    modules = _load_catalogue()
    check("catalogue", len(modules) >= 28, f"{len(modules)} check(s) registered")
    errors = plugin_report()["errors"]
    check("plugins", not errors, f"{len(errors)} plugin error(s)" if errors else "plugins load cleanly")
    for tool in ("dig", "subfinder"):
        check(tool, shutil.which(tool) is not None,
              "optional: used when present" if shutil.which(tool) else "optional: not installed", False)
    failed = [entry for entry in checks if entry["required"] and not entry["ok"]]
    if as_json:
        _print(json.dumps({"checks": checks, "guard": guard_info, "ok": not failed}, indent=2))
    else:
        for entry in checks:
            mark = "ok  " if entry["ok"] else ("FAIL" if entry["required"] else "warn")
            _print(f"[{mark}] {entry['check']:<10} {entry['detail']}")
    return 0 if not failed else 1


def setup(as_json: bool = False) -> int:
    try:
        storage = ensure_storage()
    except OSError as exc:
        _print(f"setup failed: {exc}")
        return 1
    payload = {"storage": storage, "scope": describe(),
               "next": "declare a scope, then: ./labctl websec scan example.test --preset quick"}
    if as_json:
        _print(json.dumps(payload, indent=2))
        return 0
    _print(f"storage ready: {storage}")
    if not Guard().status().get("valid"):
        _print("scope: none declared — copy console/scope.example.json to scope.json and list the hosts you own")
    _print(payload["next"])
    return 0


class _ProgressFile:
    """Best-effort JSONL progress sink; the console tails this file while a scan runs."""

    def __init__(self, path: str) -> None:
        self._handle = None
        try:
            self._handle = open(path, "a", encoding="utf-8")
        except OSError:
            self._handle = None

    def __call__(self, event: Dict[str, object]) -> None:
        if self._handle is None:
            return
        try:
            self._handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._handle.flush()
        except OSError:
            pass

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None


def scan(args) -> int:
    try:
        options = Options.build(
            args.target, preset=args.preset, modules=args.modules, active=args.active,
            cve_lookup=args.cve_lookup, scheme=args.scheme, timeout=args.timeout,
            deadline=args.deadline, scope_path=args.scope, keep_history=not args.no_history,
        )
    except ValueError as exc:
        _error(f"invalid options: {exc}")
        return 2
    sink = _ProgressFile(args.progress) if args.progress else None
    try:
        result = run_scan(options, progress=sink)
    except ScopeRefused as exc:
        _error(f"refused: {exc.reason}")
        return 1
    except ValueError as exc:
        _error(f"invalid scan: {exc}")
        return 2
    finally:
        if sink is not None:
            sink.close()
    document = report_module.build(result)
    fmt = "json" if args.json else args.format
    rendered = report_module.render(document, fmt)
    if options.keep_history:
        paths = History().append(document)
    else:
        paths = {}
    if args.diff:
        try:
            previous = History().load(options.target, str(args.diff))
        except (OSError, ValueError) as exc:
            _error(f"cannot read the previous report: {exc}")
            return 2
        if str(previous.get("target") or "") != options.target:
            _error("the previous report is for a different target")
            return 2
        diff = diff_reports(document, previous)
        _print(json.dumps(diff, indent=2, ensure_ascii=False) if fmt == "json" else _render_diff(diff))
        if paths:
            _error(f"history: {paths['history']}")
        return 0 if not result.refused else 1
    if args.out:
        target = args.out
        if os.path.isdir(target):
            target = os.path.join(target, f"{slug(options.target)}.{'md' if fmt == 'markdown' else fmt}")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        _error(f"wrote {target}")
    else:
        _print(rendered)
    if paths:
        _error(f"history: {paths['history']}")
    return 0 if not result.refused else 1


def bulk(args) -> int:
    path = args.file
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = [line.strip() for line in handle.read(200_000).splitlines()]
    except OSError as exc:
        _print(f"cannot read {path}: {exc}")
        return 2
    targets = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        candidate = line.split(",")[0].strip()
        if candidate and candidate not in targets:
            targets.append(candidate)
        if len(targets) >= MAX_BULK:
            break
    if not targets:
        _print("no targets in the file")
        return 2
    results: List[Dict[str, object]] = []

    def one(target: str) -> Dict[str, object]:
        try:
            options = Options.build(target, preset=args.preset, active=args.active,
                                    keep_history=False, timeout=args.timeout)
            scan_result = run_scan(options)
            return {"target": target, "score": scan_result.score, "grade": scan_result.grade,
                    "summary": scan_result.summary, "error": ""}
        except (ScopeRefused, ValueError) as exc:
            return {"target": target, "error": str(getattr(exc, "reason", exc))}

    workers = max(1, min(4, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for entry in pool.map(one, targets):
            results.append(entry)
    worst = 0
    for entry in results:
        code = 3 if entry.get("error") else _grade_exit(str(entry.get("grade", "")))
        worst = max(worst, code)
    if args.out:
        os.makedirs(args.out, mode=0o700, exist_ok=True)
        for entry in results:
            name = os.path.join(args.out, f"{slug(str(entry['target']))}.json")
            with open(name, "w", encoding="utf-8") as handle:
                json.dump(entry, handle, indent=2)
    if args.csv:
        writer = csv.writer(sys.stdout)
        writer.writerow(["target", "grade", "score", "critical", "high", "medium", "low", "info", "total", "error"])
        for entry in results:
            summary = entry.get("summary") or {}
            writer.writerow([
                entry.get("target"), entry.get("grade") or "", entry.get("score", "") if entry.get("grade") else "",
                summary.get("critical", 0), summary.get("high", 0), summary.get("medium", 0),
                summary.get("low", 0), summary.get("info", 0), summary.get("total", 0),
                entry.get("error", ""),
            ])
        return worst
    if args.json:
        _print(json.dumps({"targets": results, "count": len(results)}, indent=2))
        return 0
    _print(f"{'target':<40} {'grade':<6} {'score':<6} findings")
    for entry in results:
        if entry.get("error"):
            _print(f"{entry['target']:<40} {'-':<6} {'-':<6} {entry['error']}")
        else:
            _print(f"{entry['target']:<40} {entry['grade']:<6} {entry['score']:<6} "
                   f"{(entry.get('summary') or {}).get('total', 0)}")
    return worst


def report(args) -> int:
    history = History()
    if args.list or not args.name:
        reports = history.reports(args.target)
        if args.json:
            _print(json.dumps({"target": args.target, "reports": reports}, indent=2))
        else:
            for entry in reports:
                _print(f"{entry['name']}  {entry['bytes']} bytes")
        return 0
    try:
        document = history.load(args.target, args.name)
    except (OSError, ValueError) as exc:
        _print(f"cannot read the report: {exc}")
        return 2
    _print(report_module.render(document, "json" if args.json else args.format))
    return 0


def history_command(args) -> int:
    entries = History().list(args.target, limit=args.limit)
    if args.json:
        _print(json.dumps({"entries": entries}, indent=2))
        return 0
    for entry in entries:
        _print(f"{entry.get('scanned_at')}  {entry.get('target'):<36} "
               f"{entry.get('grade')} ({entry.get('score')})  {(entry.get('summary') or {}).get('total', 0)} findings")
    return 0


def plan_command(args) -> int:
    """What a scan would do, without touching the network: the review step for agents.

    Normalizes the target, asks the scope guard, and lists every selected check
    with whether it would run, so an operator (or an MCP client) can show the
    plan before any packet leaves. Intrusive checks are listed separately; they
    only run with ``--active``.
    """
    try:
        options = Options.build(args.target, preset=args.preset, modules=args.modules,
                                active=args.active, scheme=args.scheme, scope_path=args.scope)
        _load_catalogue()
        from .registry import select
        specs = select(options.modules or None, options.preset)
    except ValueError as exc:
        _error(f"invalid plan: {exc}")
        return 2
    try:
        decision = Guard(options.scope_path).check("host", options.target)
    except Exception as exc:  # no manifest, unreadable manifest: a refusal, never a crash
        decision = {"allowed": False, "reason": str(exc) or "no usable scope is declared", "rule": ""}
    checks = []
    for spec in specs:
        runs = bool(decision.get("allowed")) and (options.active or not spec.active)
        note = ""
        if not decision.get("allowed"):
            note = "the target is outside the declared scope"
        elif spec.active and not options.active:
            note = "intrusive; runs only with an active, confirmed scan"
        checks.append({"id": spec.id, "label": spec.label, "active": spec.active,
                       "weight": spec.weight, "runs": runs, "note": note})
    payload = {
        "target": options.target, "url": options.url, "preset": options.preset,
        "scheme": options.scheme, "active": options.active,
        "scope": {"allowed": bool(decision.get("allowed")), "reason": str(decision.get("reason") or ""),
                  "rule": str(decision.get("rule") or "")},
        "checks": checks,
        "intrusive": [entry["id"] for entry in checks if entry["active"] and entry["runs"]],
        "available_intrusive": [entry["id"] for entry in checks if entry["active"]],
        "runs": sum(1 for entry in checks if entry["runs"]),
    }
    if args.json:
        _print(json.dumps(payload, indent=2))
    else:
        verdict = "allowed" if payload["scope"]["allowed"] else f"refused: {payload['scope']['reason']}"
        _print(f"{payload['url']} · {options.preset} · scope {verdict}")
        for entry in checks:
            _print(f"  {'run ' if entry['runs'] else 'skip'} {entry['id']:<22} {entry['note']}")
    return 0 if payload["scope"]["allowed"] else 1


def compare_command(args) -> int:
    """Diff two stored reports of one target (older first), as ``scan --diff`` does."""
    history = History()
    try:
        before = history.load(args.target, args.old)
        after = history.load(args.target, args.new)
    except (OSError, ValueError) as exc:
        _error(f"cannot read the reports: {exc}")
        return 2
    for document in (before, after):
        if str(document.get("target") or "") != args.target.strip().lower():
            _error("both reports must belong to the requested target")
            return 2
    diff = diff_reports(after, before)
    diff["from"] = {"name": args.old, "started_at": before.get("started_at"), "preset": before.get("preset")}
    diff["to"] = {"name": args.new, "started_at": after.get("started_at"), "preset": after.get("preset")}
    _print(json.dumps(diff, indent=2, ensure_ascii=False) if args.json else _render_diff(diff))
    return 0


def prefs_command(args) -> int:
    from . import preferences
    if args.save is None:
        payload = preferences.load()
    else:
        try:
            payload = preferences.save(json.loads(args.save))
        except ValueError as exc:  # PreferencesError and invalid JSON
            _error(f"invalid preferences: {exc}")
            return 2
        except OSError as exc:
            _error(f"cannot save the preferences: {exc}")
            return 1
    if args.json:
        _print(json.dumps(payload, indent=2))
    else:
        scan_prefs = payload["preferences"]["scan"]
        _print(f"target {scan_prefs['target'] or '-'} · {scan_prefs['preset']} · {scan_prefs['scheme']} · "
               f"{len(scan_prefs['modules']) or 'preset'} checks")
        if payload.get("configError"):
            _print(f"note: {payload['configError']}")
    return 0


def guides_command(args) -> int:
    from .guides import guides
    payload = guides()
    if args.json:
        _print(json.dumps(payload, indent=2))
        return 0
    for guide in payload["guides"]:
        _print(f"## {guide['title']}")
        for point in guide["points"]:
            _print(f"- {point}")
        _print("")
    return 0


def modules(args) -> int:
    entries = _load_catalogue()
    if args.json:
        from .registry import select
        presets = {name: [spec.id for spec in select(None, name)] for name in ("quick", "standard", "full")}
        _print(json.dumps({"modules": entries, "presets": presets, "plugins": plugin_report()}, indent=2))
        return 0
    for entry in entries:
        flag = "active" if entry["active"] else entry["group"]
        _print(f"{entry['id']:<22} {flag:<10} {entry['label']}")
    return 0


def plugins(args) -> int:
    _load_catalogue()
    info = plugin_report()
    if args.json:
        _print(json.dumps(info, indent=2))
        return 0
    for name in info["loaded"]:
        _print(f"loaded  {name}")
    for error in info["errors"]:
        _print(f"error   {error['plugin']}: {error['error']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websec", description="Web Sec Lab — scope-guarded web posture assessment")
    parser.add_argument("--version", action="version", version=f"Web Sec Lab {VERSION}")
    sub = parser.add_subparsers(dest="command")

    p_status = sub.add_parser("status", help="readiness without touching the network")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=lambda a: status(a.json))

    p_doctor = sub.add_parser("doctor", help="check Python, storage, scope and plugins")
    p_doctor.add_argument("--json", action="store_true")
    p_doctor.set_defaults(func=lambda a: doctor(a.json))

    p_setup = sub.add_parser("setup", help="create the private storage tree")
    p_setup.add_argument("--json", action="store_true")
    p_setup.set_defaults(func=lambda a: setup(a.json))

    p_scan = sub.add_parser("scan", help="scan one target")
    p_scan.add_argument("target")
    p_scan.add_argument("--preset", default="standard", choices=("quick", "standard", "full"))
    p_scan.add_argument("--modules", default="", help="comma-separated module ids")
    p_scan.add_argument("--active", action="store_true", help="allow intrusive checks")
    p_scan.add_argument("--cve-lookup", action="store_true", help="query NVD for banners")
    p_scan.add_argument("--scheme", default="https", choices=("http", "https"))
    p_scan.add_argument("--format", default="markdown", choices=("json", "sarif", "markdown", "text", "html"))
    p_scan.add_argument("--json", action="store_true", help="shortcut for --format json")
    p_scan.add_argument("--diff", default="",
                        help="compare against a stored report name of the same target")
    p_scan.add_argument("--progress", default="",
                        help="append JSONL progress events to a file while the scan runs")
    p_scan.add_argument("--out", default="")
    p_scan.add_argument("--no-history", action="store_true")
    p_scan.add_argument("--timeout", type=float, default=6.0)
    p_scan.add_argument("--deadline", type=float, default=60.0)
    p_scan.add_argument("--scope", default="", help="scope manifest path")
    p_scan.set_defaults(func=scan)

    p_bulk = sub.add_parser("bulk", help="scan a file of targets, four at a time")
    p_bulk.add_argument("file")
    p_bulk.add_argument("--preset", default="quick", choices=("quick", "standard", "full"))
    p_bulk.add_argument("--active", action="store_true")
    p_bulk.add_argument("--json", action="store_true")
    p_bulk.add_argument("--csv", action="store_true",
                        help="write a CSV summary and exit with the worst grade "
                             "(0 through B, 1 C, 2 D, 3 F or refused)")
    p_bulk.add_argument("--out", default="")
    p_bulk.add_argument("--timeout", type=float, default=6.0)
    p_bulk.set_defaults(func=bulk)

    p_report = sub.add_parser("report", help="list or render a stored report")
    p_report.add_argument("--target", required=True)
    p_report.add_argument("--name", default="")
    p_report.add_argument("--list", action="store_true")
    p_report.add_argument("--format", default="markdown", choices=("json", "sarif", "markdown", "text", "html"))
    p_report.add_argument("--json", action="store_true")
    p_report.set_defaults(func=report)

    p_history = sub.add_parser("history", help="recent scans")
    p_history.add_argument("--target", default="")
    p_history.add_argument("--limit", type=int, default=20)
    p_history.add_argument("--json", action="store_true")
    p_history.set_defaults(func=history_command)

    p_plan = sub.add_parser("plan", help="what a scan would run, without touching the network")
    p_plan.add_argument("target")
    p_plan.add_argument("--preset", default="standard", choices=("quick", "standard", "full"))
    p_plan.add_argument("--modules", default="", help="comma-separated module ids")
    p_plan.add_argument("--active", action="store_true", help="plan the intrusive checks too")
    p_plan.add_argument("--scheme", default="https", choices=("http", "https"))
    p_plan.add_argument("--scope", default="", help="scope manifest path")
    p_plan.add_argument("--json", action="store_true")
    p_plan.set_defaults(func=plan_command)

    p_compare = sub.add_parser("compare", help="what changed between two stored reports of one target")
    p_compare.add_argument("--target", required=True)
    p_compare.add_argument("--old", required=True, help="the earlier report name")
    p_compare.add_argument("--new", required=True, help="the later report name")
    p_compare.add_argument("--json", action="store_true")
    p_compare.set_defaults(func=compare_command)

    p_prefs = sub.add_parser("prefs", help="read or save the workbench choices")
    p_prefs.add_argument("--save", default=None, metavar="JSON", help="validate and store a preferences object")
    p_prefs.add_argument("--json", action="store_true")
    p_prefs.set_defaults(func=prefs_command)

    p_guides = sub.add_parser("guides", help="the SecOps guides behind each check")
    p_guides.add_argument("--json", action="store_true")
    p_guides.set_defaults(func=guides_command)

    p_modules = sub.add_parser("modules", help="the registered check catalogue")
    p_modules.add_argument("--json", action="store_true")
    p_modules.set_defaults(func=modules)

    p_plugins = sub.add_parser("plugins", help="plugin folders and load errors")
    p_plugins.add_argument("--json", action="store_true")
    p_plugins.set_defaults(func=plugins)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        _print("interrupted")
        return 130
