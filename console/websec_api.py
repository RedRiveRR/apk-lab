"""Web Sec Lab HTTP contracts (``/api/websec/...``).

The console never re-implements the engine: it probes readiness, starts a scan as
a child process, and serves the JSON/SARIF/Markdown the engine produced. Every
request is typed; an unknown route, field or report name fails explicitly.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from websec_control import lab_status

TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$", re.ASCII)
MODULE_ID = re.compile(r"^[a-z][a-z0-9_]{0,47}$", re.ASCII)
REPORT_NAME = re.compile(r"^[0-9A-Za-z._-]{1,120}\.json$", re.ASCII)
FORMATS = {"json", "sarif", "markdown", "md", "text", "html"}
PRESETS = {"quick", "standard", "full"}
PAYLOAD_KEYS = {"target", "preset", "modules", "active", "cveLookup", "scheme"}
MAX_MODULES = 40
MAX_BULK = 20
MAX_JOBS = 20
MAX_OUTPUT = 4 * 1024 * 1024
MAX_BODY = 64 * 1024


class WebSecError(ValueError):
    """A request the lab refused, with the HTTP status to answer."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


_INSTANCES: Dict[str, "WebSecAPI"] = {}


def api_for(root: str) -> "WebSecAPI":
    """One API object per checkout, because scan jobs live in its memory.

    The console builds a request handler per request; a per-handler API object
    would forget every running scan between two polls.
    """
    key = os.path.realpath(root)
    if key not in _INSTANCES:
        _INSTANCES[key] = WebSecAPI(key)
    return _INSTANCES[key]


class WebSecAPI:
    def __init__(self, root: str, python: Optional[str] = None):
        self.root = str(root)
        self.lab = Path(root) / "web-sec"
        self.runner = self.lab / "run.py"
        self.python = python or os.environ.get("WEBSEC_PYTHON") or sys.executable
        self.storage = Path(os.environ.get("WEBSEC_STORAGE") or (self.lab / "storage"))
        self.jobs: Dict[str, dict] = {}
        self.lock = threading.Lock()
        self._status_cache = (0.0, {})

    # ── process helpers ──────────────────────────────────────────────────────

    def _run(self, args: List[str], timeout: float = 20.0) -> subprocess.CompletedProcess:
        if not self.runner.is_file():
            raise WebSecError(501, "The web-sec lab is not installed in this checkout")
        try:
            return subprocess.run([self.python, str(self.runner), *args],
                                  capture_output=True, text=True, timeout=timeout,
                                  cwd=self.root, check=False)
        except subprocess.TimeoutExpired:
            raise WebSecError(504, "The Web Sec Lab engine did not answer in time") from None
        except OSError as exc:
            raise WebSecError(500, f"The Web Sec Lab engine could not start: {exc}") from None

    def _json(self, args: List[str], timeout: float = 20.0) -> dict:
        result = self._run(args, timeout)
        if len(result.stdout) > MAX_OUTPUT:
            raise WebSecError(502, "The engine answered with more data than the console accepts")
        if result.returncode != 0 and not result.stdout.strip():
            message = (result.stderr or "the engine failed").strip().splitlines()[-1][:500]
            raise WebSecError(502, message)
        try:
            payload = json.loads(result.stdout)
        except ValueError:
            raise WebSecError(502, "The engine answered with something that is not JSON") from None
        if not isinstance(payload, dict):
            raise WebSecError(502, "The engine answered with an unexpected shape")
        return payload

    # ── readiness ────────────────────────────────────────────────────────────

    def status(self) -> dict:
        now = time.monotonic()
        stamp, cached = self._status_cache
        if cached and now - stamp < 3.0:
            return cached
        platform = "windows" if os.name == "nt" else "macos" if sys.platform == "darwin" else "linux"
        state = lab_status(self.root, platform)
        payload = {
            "state": state["state"],
            "provider": state["provider"],
            "requirements": state["requirements"],
            "reasons": state["reasons"],
            "notes": state["notes"],
            "version": state.get("version", ""),
            "python": self.python,
            "storage": str(self.storage),
        }
        self._status_cache = (now, payload)
        return payload

    def scope(self) -> dict:
        return self.status()

    def modules(self) -> dict:
        return self._json(["modules", "--json"], timeout=20)

    def plugins(self) -> dict:
        return self._json(["plugins", "--json"], timeout=20)

    # ── scans ────────────────────────────────────────────────────────────────

    def _validate(self, payload: dict) -> dict:
        unknown = set(payload) - PAYLOAD_KEYS
        if unknown:
            raise WebSecError(400, "Unknown field(s): " + ", ".join(sorted(unknown)))
        target = payload.get("target")
        if not isinstance(target, str) or not TARGET.match(target.strip()):
            raise WebSecError(400, "A target host name or address is required")
        target = target.strip().lower()
        preset = payload.get("preset", "standard")
        if preset not in PRESETS:
            raise WebSecError(400, "preset must be quick, standard or full")
        modules = payload.get("modules") or []
        if not isinstance(modules, list) or len(modules) > MAX_MODULES:
            raise WebSecError(400, "modules must be a list of at most 40 ids")
        for module in modules:
            if not isinstance(module, str) or not MODULE_ID.match(module):
                raise WebSecError(400, "each module id must look like dns_records")
        scheme = payload.get("scheme", "https")
        if scheme not in ("http", "https"):
            raise WebSecError(400, "scheme must be http or https")
        return {"target": target, "preset": preset, "modules": modules, "scheme": scheme,
                "active": bool(payload.get("active")), "cveLookup": bool(payload.get("cveLookup"))}

    def start_scan(self, payload: dict) -> dict:
        if len(json.dumps(payload, allow_nan=False).encode("utf-8")) > MAX_BODY:
            raise WebSecError(413, "The request body is too large")
        options = self._validate(payload)
        refusal = self._scope_refusal(options["target"])
        if refusal:
            raise WebSecError(403, refusal)
        with self.lock:
            if any(job["state"] == "running" for job in self.jobs.values()):
                raise WebSecError(409, "A scan is already running; wait for it or cancel it")
            if not self.runner.is_file():
                raise WebSecError(501, "The web-sec lab is not installed in this checkout")
            job_id = uuid.uuid4().hex[:12]
            directory = self.storage / "jobs" / job_id
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            stdout_path = directory / "report.json"
            stderr_path = directory / "engine.log"
            args = [self.python, str(self.runner), "scan", options["target"],
                    "--preset", options["preset"], "--scheme", options["scheme"],
                    "--format", "json"]
            if options["modules"]:
                args += ["--modules", ",".join(options["modules"])]
            if options["active"]:
                args.append("--active")
            if options["cveLookup"]:
                args.append("--cve-lookup")
            with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
                try:
                    process = subprocess.Popen(args, cwd=self.root, stdout=stdout, stderr=stderr,
                                               stdin=subprocess.DEVNULL, start_new_session=True)
                except OSError as exc:
                    raise WebSecError(500, f"The scan could not start: {exc}") from None
            job = {"id": job_id, "state": "running", "target": options["target"],
                   "preset": options["preset"], "active": options["active"],
                   "started": time.time(), "pid": process.pid, "process": process,
                   "stdout": str(stdout_path), "stderr": str(stderr_path)}
            self.jobs[job_id] = job
            self._prune_jobs()
            return self._job_view(job)

    def _scope_refusal(self, target: str) -> str:
        """Ask the repository guard before spawning a child; empty when allowed."""
        guard = Path(self.root) / "console/scope_guard.py"
        if not guard.is_file():
            return ""
        try:
            result = subprocess.run([self.python, str(guard), "check", "--json", "host", target],
                                    capture_output=True, text=True, timeout=10, cwd=self.root)
            decision = json.loads(result.stdout or "{}")
        except (OSError, ValueError, subprocess.SubprocessError):
            return ""
        if decision.get("allowed") is False:
            return str(decision.get("reason") or "the target is outside the declared scope")
        return ""

    def _prune_jobs(self) -> None:
        finished = sorted((job for job in self.jobs.values() if job["state"] != "running"),
                          key=lambda job: job["started"])
        while len(self.jobs) > MAX_JOBS and finished:
            stale = finished.pop(0)
            self.jobs.pop(stale["id"], None)

    def _job_view(self, job: dict) -> dict:
        view = {"id": job["id"], "state": job["state"], "kind": job.get("kind", "scan"),
                "target": job.get("target", ""), "preset": job["preset"],
                "active": job.get("active", False), "started": job["started"]}
        if job["state"] == "done":
            if job.get("kind") == "bulk":
                view["results"] = job.get("results")
            else:
                view["report"] = job.get("report")
        if job["state"] == "error":
            view["error"] = job.get("error", "the scan failed")
        return view

    def job(self, job_id: str) -> dict:
        job = self.jobs.get(job_id)
        if job is None:
            raise WebSecError(404, "Unknown scan id")
        if job["state"] == "running":
            process = job["process"]
            if process.poll() is None:
                return self._job_view(job)
            job["state"] = "error" if process.returncode else "done"
            job["finished"] = time.time()
            if process.returncode:
                job["error"] = self._tail(job["stderr"]) or f"the engine exited with {process.returncode}"
            else:
                try:
                    payload = self._read_json(job["stdout"])
                except WebSecError as exc:
                    job["state"] = "error"
                    job["error"] = str(exc)
                else:
                    if job.get("kind") == "bulk":
                        job["results"] = payload
                    else:
                        job["report"] = payload
        return self._job_view(job)

    def _tail(self, path: str) -> str:
        try:
            if os.path.getsize(path) > MAX_OUTPUT:
                return "the engine log is larger than the console accepts"
            data = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        lines = [line for line in data.strip().splitlines() if line.strip()]
        return lines[-1][:500] if lines else ""

    def _read_json(self, path: str) -> dict:
        try:
            if os.path.getsize(path) > MAX_OUTPUT:
                raise WebSecError(502, "The report is larger than the console accepts")
            payload = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            raise WebSecError(502, f"The report could not be read: {exc}") from None
        except ValueError:
            raise WebSecError(502, "The engine produced a report that is not JSON") from None
        if not isinstance(payload, dict):
            raise WebSecError(502, "The report has an unexpected shape")
        return payload

    def cancel(self, job_id: str) -> dict:
        job = self.jobs.get(job_id)
        if job is None:
            raise WebSecError(404, "Unknown scan id")
        if job["state"] == "running" and job["process"].poll() is None:
            try:
                os.killpg(os.getpgid(job["process"].pid), signal.SIGTERM)
            except OSError as exc:
                raise WebSecError(500, f"The scan could not be stopped: {exc}") from None
            try:
                job["process"].wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(job["process"].pid), signal.SIGKILL)
                except OSError:
                    pass
            job["state"] = "cancelled"
            job["finished"] = time.time()
        return self._job_view(job)

    # ── bulk validation ──

    def _validate_bulk(self, payload: dict) -> dict:
        """A bulk run is a bounded list of the same typed targets, passive only."""
        unknown = set(payload) - {"targets", "preset"}
        if unknown:
            raise WebSecError(400, "Unknown field(s): " + ", ".join(sorted(unknown)))
        targets = payload.get("targets")
        if not isinstance(targets, list) or not targets:
            raise WebSecError(400, "targets must be a non-empty list")
        if len(targets) > MAX_BULK:
            raise WebSecError(400, f"at most {MAX_BULK} targets per bulk run")
        cleaned: List[str] = []
        for target in targets:
            if not isinstance(target, str) or not TARGET.match(target.strip()):
                raise WebSecError(400, "each target must look like example.test")
            candidate = target.strip().lower()
            if candidate not in cleaned:
                cleaned.append(candidate)
        preset = payload.get("preset", "quick")
        if preset not in PRESETS:
            raise WebSecError(400, "preset must be quick, standard or full")
        return {"targets": cleaned, "preset": preset}

    def start_bulk(self, payload: dict) -> dict:
        """Run the engine ``bulk`` command as one child; per-target refusals stay per-target.

        The engine consults the scope guard for every target, so a target outside
        the declared scope comes back as an error row instead of failing the run.
        """
        if len(json.dumps(payload, allow_nan=False).encode("utf-8")) > MAX_BODY:
            raise WebSecError(413, "The request body is too large")
        options = self._validate_bulk(payload)
        with self.lock:
            if any(job["state"] == "running" for job in self.jobs.values()):
                raise WebSecError(409, "A scan is already running; wait for it or cancel it")
            if not self.runner.is_file():
                raise WebSecError(501, "The web-sec lab is not installed in this checkout")
            job_id = uuid.uuid4().hex[:12]
            directory = self.storage / "jobs" / job_id
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            targets_path = directory / "targets.txt"
            stdout_path = directory / "bulk.json"
            stderr_path = directory / "engine.log"
            targets_path.write_text("\n".join(options["targets"]) + "\n", encoding="utf-8")
            os.chmod(targets_path, 0o600)
            args = [self.python, str(self.runner), "bulk", str(targets_path),
                    "--preset", options["preset"], "--json"]
            with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
                try:
                    process = subprocess.Popen(args, cwd=self.root, stdout=stdout, stderr=stderr,
                                               stdin=subprocess.DEVNULL, start_new_session=True)
                except OSError as exc:
                    raise WebSecError(500, f"The bulk run could not start: {exc}") from None
            job = {"id": job_id, "state": "running", "kind": "bulk",
                   "target": "", "preset": options["preset"], "active": False,
                   "started": time.time(), "pid": process.pid, "process": process,
                   "targets": options["targets"],
                   "stdout": str(stdout_path), "stderr": str(stderr_path)}
            self.jobs[job_id] = job
            self._prune_jobs()
            return self._job_view(job)

    # ── stored reports ───────────────────────────────────────────────────────

    def history(self, target: Optional[str] = None, limit: int = 20) -> dict:
        if target is not None and (not isinstance(target, str) or not TARGET.match(target)):
            raise WebSecError(400, "Invalid target")
        limit = max(1, min(int(limit or 20), 100))
        args = ["history", "--json", "--limit", str(limit)]
        if target:
            args += ["--target", target]
        return self._json(args, timeout=20)

    def reports(self, target: str) -> dict:
        if not isinstance(target, str) or not TARGET.match(target):
            raise WebSecError(400, "Invalid target")
        return self._json(["report", "--target", target, "--list", "--json"], timeout=20)

    def report(self, target: str, name: str, fmt: str = "json") -> str:
        if not isinstance(target, str) or not TARGET.match(target):
            raise WebSecError(400, "Invalid target")
        if not isinstance(name, str) or not REPORT_NAME.match(name):
            raise WebSecError(400, "Invalid report name")
        if fmt not in FORMATS:
            raise WebSecError(400, "format must be json, sarif, markdown, text or html")
        result = self._run(["report", "--target", target, "--name", name, "--format", fmt], timeout=20)
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "the report could not be rendered").strip()
            raise WebSecError(404, message.splitlines()[-1][:500])
        if len(result.stdout) > MAX_OUTPUT:
            raise WebSecError(502, "The rendered report is larger than the console accepts")
        return result.stdout

    # ── routing ──────────────────────────────────────────────────────────────

    def get(self, path: str, query: dict) -> dict:
        if path == "/api/websec/status":
            return self.status()
        if path == "/api/websec/modules":
            return self.modules()
        if path == "/api/websec/scope":
            return self.scope()
        if path == "/api/websec/plugins":
            return self.plugins()
        if path.startswith("/api/websec/scans/"):
            return self.job(path.rsplit("/", 1)[-1])
        if path.startswith("/api/websec/bulk/"):
            return self.job(path.rsplit("/", 1)[-1])
        if path == "/api/websec/history":
            target = (query.get("target") or [""])[0] or None
            limit = (query.get("limit") or ["20"])[0]
            try:
                limit_value = int(limit)
            except ValueError:
                raise WebSecError(400, "limit must be a number") from None
            return self.history(target, limit_value)
        if path == "/api/websec/reports":
            target = (query.get("target") or [""])[0]
            return self.reports(target)
        if path == "/api/websec/report":
            target = (query.get("target") or [""])[0]
            name = (query.get("name") or [""])[0]
            fmt = (query.get("format") or ["json"])[0]
            return {"content": self.report(target, name, fmt), "format": fmt, "name": name}
        raise WebSecError(404, f"Unknown Web Sec Lab route: {path}")

    def post(self, path: str, data: dict) -> dict:
        if path == "/api/websec/scans":
            return self.start_scan(data)
        if path == "/api/websec/bulk":
            return self.start_bulk(data)
        raise WebSecError(404, f"Unknown Web Sec Lab route: {path}")

    def delete(self, path: str) -> dict:
        if path.startswith("/api/websec/scans/"):
            return self.cancel(path.rsplit("/", 1)[-1])
        if path.startswith("/api/websec/bulk/"):
            return self.cancel(path.rsplit("/", 1)[-1])
        raise WebSecError(404, f"Unknown Web Sec Lab route: {path}")
