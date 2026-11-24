"""Command line for the Web Sec Lab: status, doctor, scan, bulk, reports."""
from __future__ import annotations

import argparse
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
    try:
        result = run_scan(options)
    except ScopeRefused as exc:
        _error(f"refused: {exc.reason}")
        return 1
    except ValueError as exc:
        _error(f"invalid scan: {exc}")
        return 2
    document = report_module.build(result)
    fmt = "json" if args.json else args.format
    rendered = report_module.render(document, fmt)
    if options.keep_history:
        paths = History().append(document)
    else:
        paths = {}
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
    if args.out:
        os.makedirs(args.out, mode=0o700, exist_ok=True)
        for entry in results:
            name = os.path.join(args.out, f"{slug(str(entry['target']))}.json")
            with open(name, "w", encoding="utf-8") as handle:
                json.dump(entry, handle, indent=2)
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
    return 0


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


def modules(args) -> int:
    entries = _load_catalogue()
    if args.json:
        _print(json.dumps({"modules": entries, "plugins": plugin_report()}, indent=2))
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
