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
        lines = lines[-MAX_HISTORY:]
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        os.chmod(path, 0o600)
        directory = self.reports_dir(target)
        report_path = os.path.join(directory, name)
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
        os.chmod(report_path, 0o600)
        self._prune(directory)
        return {"history": path, "report": report_path, "name": name}

    def _prune(self, directory: str) -> None:
        try:
            entries = sorted(
                (entry for entry in os.listdir(directory) if entry.endswith(".json")),
                key=lambda entry: os.path.getmtime(os.path.join(directory, entry)),
            )
        except OSError:
            return
        for stale in entries[:-MAX_REPORTS]:
            try:
                os.remove(os.path.join(directory, stale))
            except OSError:
                continue

    def list(self, target: Optional[str] = None, limit: int = 20) -> List[Dict[str, object]]:
        if target:
            return self._read(self._history_file(target))[-limit:][::-1]
        base = os.path.join(self._ensure(), "history")
        collected: List[Dict[str, object]] = []
        try:
            names = [name for name in os.listdir(base) if name.endswith(".jsonl")]
        except OSError:
            return []
        for name in names:
            collected.extend(self._read(os.path.join(base, name)))
        collected.sort(key=lambda entry: str(entry.get("scanned_at") or ""), reverse=True)
        return collected[:limit]

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
