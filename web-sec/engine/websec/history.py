"""Bounded, private history: one JSONL summary line per scan plus the full report.

Stored under ``web-sec/storage`` (0700) and pruned so a long-running lab does not
grow without limit. The dashboard reads this through the console, never directly.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Dict, List, Optional

from .config import default_storage, ensure_storage

MAX_HISTORY = 50
MAX_REPORTS = 20
MAX_FAVOURITES = 10   # per target; a favourite survives pruning, so the count is capped
FAVOURITES = "favourites.json"
MAX_READ = 4 * 1024 * 1024
_NAME = re.compile(r"^[0-9A-Za-z._-]{1,120}\.json$")


def slug(target: str) -> str:
    value = re.sub(r"[^a-z0-9.-]+", "-", target.lower()).strip("-")
    return value[:100] or "target"


class History:
    def __init__(self, root: Optional[str] = None):
        self.root = root or default_storage()

    def _ensure(self) -> str:
        return ensure_storage(self.root)

    def _history_file(self, target: str) -> str:
        return os.path.join(self._ensure(), "history", f"{slug(target)}.jsonl")

    def reports_dir(self, target: str) -> str:
        directory = os.path.join(self._ensure(), "reports", slug(target))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        return directory

    def append(self, document: Dict[str, object]) -> Dict[str, str]:
        """Store the summary line and the full report; return both paths."""
        target = str(document.get("target", ""))
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        name = f"{stamp}-{document.get('score', 0)}.json"
        summary = {
            "target": target,
            "scanned_at": document.get("generated_at"),
            "score": document.get("score"),
            "grade": document.get("grade"),
            "summary": document.get("summary"),
            "preset": document.get("preset"),
            "active": document.get("active"),
            "refused": document.get("refused"),
            "name": name,
        }
        path = self._history_file(target)
        lines: List[str] = []
        try:
            with open(path, encoding="utf-8") as handle:
                lines = handle.read(MAX_READ).splitlines()
        except OSError:
            lines = []
        lines.append(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        if len(lines) > MAX_HISTORY:
            keep = set(self.favourites().get(target, []))
            pinned = [line for line in lines[:-MAX_HISTORY] if any(f'"name": "{name}"' in line for name in keep)]
            lines = pinned + lines[-MAX_HISTORY:]
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        os.chmod(path, 0o600)
        directory = self.reports_dir(target)
        report_path = os.path.join(directory, name)
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
        os.chmod(report_path, 0o600)
        self._prune(directory, set(self.favourites().get(target, [])))
        return {"history": path, "report": report_path, "name": name}

    def _prune(self, directory: str, keep: Optional[set] = None) -> None:
        keep = keep or set()
        try:
            entries = sorted(
                (entry for entry in os.listdir(directory) if entry.endswith(".json") and entry not in keep),
                key=lambda entry: os.path.getmtime(os.path.join(directory, entry)),
            )
        except OSError:
            return
        for stale in entries[:-max(1, MAX_REPORTS - len(keep))]:
            try:
                os.remove(os.path.join(directory, stale))
            except OSError:
                continue

    # ── favourites, delete, clear, statistics ───────────────────────────────

    def _favourites_path(self) -> str:
        return os.path.join(self._ensure(), FAVOURITES)

    def favourites(self) -> Dict[str, List[str]]:
        try:
            with open(self._favourites_path(), encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
        return {str(target): [str(name) for name in names if _NAME.match(str(name))][:MAX_FAVOURITES]
                for target, names in raw.items() if isinstance(names, list)}

    def _write_favourites(self, favourites: Dict[str, List[str]]) -> None:
        path = self._favourites_path()
        temporary = f"{path}.tmp-{os.getpid()}"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({target: names for target, names in favourites.items() if names}, handle, indent=2)
        os.replace(temporary, path)

    def set_favourite(self, target: str, name: str, on: bool = True) -> Dict[str, object]:
        self.load(target, name)  # validates the name and that the report exists
        favourites = self.favourites()
        names = [entry for entry in favourites.get(target, []) if entry != name]
        if on:
            if len(names) >= MAX_FAVOURITES:
                raise ValueError(f"at most {MAX_FAVOURITES} favourite runs per target")
            names.append(name)
        favourites[target] = names
        self._write_favourites(favourites)
        return {"target": target, "name": name, "favourite": on}

    def delete(self, target: str, names: List[str]) -> Dict[str, object]:
        """Remove stored runs (report file and history line) by name."""
        if not names or any(not isinstance(name, str) or not _NAME.match(name) for name in names):
            raise ValueError("name one or more stored report names")
        directory = os.path.realpath(self.reports_dir(target))
        removed = 0
        for name in set(names):
            path = os.path.realpath(os.path.join(directory, name))
            if os.path.dirname(path) != directory:
                raise ValueError("report name escapes the report folder")
            try:
                os.remove(path)
                removed += 1
            except FileNotFoundError:
                pass
        doomed = set(names)
        kept = [entry for entry in self._read(self._history_file(target)) if entry.get("name") not in doomed]
        self._rewrite(target, kept)
        favourites = self.favourites()
        if target in favourites:
            favourites[target] = [name for name in favourites[target] if name not in doomed]
            self._write_favourites(favourites)
        return {"target": target, "deleted": removed}

    def _rewrite(self, target: str, entries: List[Dict[str, object]]) -> None:
        path = self._history_file(target)
        if not entries:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(json.dumps(entry, ensure_ascii=False, sort_keys=True) for entry in entries) + "\n")
        os.chmod(path, 0o600)

    def targets(self) -> List[str]:
        base = os.path.join(self._ensure(), "history")
        found = []
        for name in sorted(os.listdir(base)) if os.path.isdir(base) else []:
            if name.endswith(".jsonl"):
                entries = self._read(os.path.join(base, name))
                if entries and entries[-1].get("target"):
                    found.append(str(entries[-1]["target"]))
        return found

    def clear(self, target: Optional[str] = None) -> Dict[str, object]:
        """Remove every stored run of one target, or of every target when none is named."""
        chosen = [target] if target else self.targets()
        removed = 0
        for host in chosen:
            directory = self.reports_dir(host)
            for name in os.listdir(directory):
                if _NAME.match(name):
                    try:
                        os.remove(os.path.join(directory, name))
                        removed += 1
                    except OSError:
                        continue
            self._rewrite(host, [])
        favourites = self.favourites()
        for host in chosen:
            favourites.pop(host, None)
        self._write_favourites(favourites if target else {})
        return {"targets": len(chosen), "deleted": removed}

    def stats(self) -> Dict[str, object]:
        """Totals over every target and the latest run of each."""
        latest: List[Dict[str, object]] = []
        runs = 0
        reports = 0
        size = 0
        grades: Dict[str, int] = {}
        severities = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
        favourites = self.favourites()
        for host in self.targets():
            entries = self._read(self._history_file(host))
            runs += len(entries)
            stored = self.reports(host)
            reports += len(stored)
            size += sum(int(entry["bytes"]) for entry in stored)
            if entries:
                last = entries[-1]
                latest.append({"target": host, "grade": last.get("grade"), "score": last.get("score"),
                               "scanned_at": last.get("scanned_at"), "name": last.get("name"),
                               "findings": (last.get("summary") or {}).get("total", 0)})
                grade = str(last.get("grade") or "?")[:1]
                grades[grade] = grades.get(grade, 0) + 1
                for key in severities:
                    severities[key] += int((last.get("summary") or {}).get(key, 0) or 0)
        latest.sort(key=lambda entry: str(entry.get("scanned_at") or ""), reverse=True)
        return {"targets": len(latest), "runs": runs, "reports": reports, "bytes": size,
                "favourites": sum(len(names) for names in favourites.values()),
                "grades": grades, "latestFindings": severities, "latest": latest}

    def list(self, target: Optional[str] = None, limit: int = 20) -> List[Dict[str, object]]:
        favourites = self.favourites()

        def mark(entries: List[Dict[str, object]]) -> List[Dict[str, object]]:
            return [{**entry, "favourite": entry.get("name") in favourites.get(str(entry.get("target")), [])}
                    for entry in entries]

        if target:
            return mark(self._read(self._history_file(target))[-limit:][::-1])
        base = os.path.join(self._ensure(), "history")
        collected: List[Dict[str, object]] = []
        try:
            names = [name for name in os.listdir(base) if name.endswith(".jsonl")]
        except OSError:
            return []
        for name in names:
            collected.extend(self._read(os.path.join(base, name)))
        collected.sort(key=lambda entry: str(entry.get("scanned_at") or ""), reverse=True)
        return mark(collected[:limit])

    def _read(self, path: str) -> List[Dict[str, object]]:
        try:
            with open(path, encoding="utf-8") as handle:
                raw = handle.read(MAX_READ)
        except OSError:
            return []
        entries = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                entries.append(value)
        return entries

    def reports(self, target: str) -> List[Dict[str, object]]:
        directory = self.reports_dir(target)
        entries = []
        try:
            names = os.listdir(directory)
        except OSError:
            return []
        for name in names:
            if not _NAME.match(name):
                continue
            path = os.path.join(directory, name)
            try:
                stat = os.stat(path)
            except OSError:
                continue
            entries.append({"name": name, "bytes": stat.st_size, "modified": int(stat.st_mtime)})
        entries.sort(key=lambda entry: entry["modified"], reverse=True)
        return entries[:MAX_REPORTS]

    def load(self, target: str, name: str) -> Dict[str, object]:
        if not _NAME.match(name):
            raise ValueError("report name is not allowed")
        directory = os.path.realpath(self.reports_dir(target))
        path = os.path.realpath(os.path.join(directory, name))
        if os.path.dirname(path) != directory:
            raise ValueError("report name escapes the report folder")
        if os.path.getsize(path) > MAX_READ:
            raise ValueError("report is larger than 4 MiB")
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
