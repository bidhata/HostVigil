"""Optional SpearSpray backend adapter for credential spraying workflows."""

from __future__ import annotations

import hashlib
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class SpearSprayAdapter:
    """Runs SpearSpray and normalizes output for HostVigil workflows."""

    def __init__(self, config: dict, db_path: str):
        self.config = config
        self.db_path = db_path

    def run(self) -> dict:
        """Execute SpearSpray and return normalized result payload."""
        spearspray_cfg = self.config.get("spearspray", {})
        cmd = self._build_command(spearspray_cfg)
        timeout = int(self.config.get("timeout_seconds", 1800))

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(Path(self.db_path).parent),
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        parsed = self._parse_successes(stdout + "\n" + stderr)
        stored = self._store_parsed_results(parsed, spearspray_cfg)

        return {
            "backend": "spearspray",
            "command": cmd,
            "returncode": proc.returncode,
            "stdout_tail": self._tail(stdout),
            "stderr_tail": self._tail(stderr),
            "results": stored,
            "success_count": len([r for r in stored if r.get("success")]),
        }

    def _build_command(self, spearspray_cfg: dict) -> list[str]:
        binary_path = str(spearspray_cfg.get("binary_path", "spearspray")).strip()
        if not binary_path:
            raise ValueError("credential_spray.spearspray.binary_path is required")
        resolved = shutil.which(binary_path) or binary_path
        if shutil.which(resolved) is None and not Path(resolved).exists():
            raise FileNotFoundError(f"SpearSpray binary not found: {binary_path}")

        required = ("domain", "username", "password", "domain_controller")
        missing = [key for key in required if not str(spearspray_cfg.get(key, "")).strip()]
        if missing:
            raise ValueError(f"SpearSpray config missing required fields: {', '.join(missing)}")

        cmd = [
            resolved,
            "-d",
            str(spearspray_cfg["domain"]),
            "-u",
            str(spearspray_cfg["username"]),
            "-p",
            str(spearspray_cfg["password"]),
            "-dc",
            str(spearspray_cfg["domain_controller"]),
            "-t",
            str(int(spearspray_cfg.get("threads", 5))),
            "-thr",
            str(int(spearspray_cfg.get("threshold", 2))),
            "-s",
        ]
        if bool(spearspray_cfg.get("use_ssl", False)):
            cmd.append("--ssl")
        jitter = str(spearspray_cfg.get("jitter", "")).strip()
        if jitter:
            cmd.extend(["-j", jitter])
        max_rps = spearspray_cfg.get("max_rps")
        if max_rps not in (None, "", 0):
            cmd.extend(["--max-rps", str(max_rps)])
        extra = str(spearspray_cfg.get("extra", "")).strip()
        if extra:
            cmd.extend(["-x", extra])
        separator = str(spearspray_cfg.get("separator", "")).strip()
        if separator:
            cmd.extend(["-sep", separator])
        suffix = str(spearspray_cfg.get("suffix", "")).strip()
        if suffix:
            cmd.extend(["-suf", suffix])
        query = str(spearspray_cfg.get("query", "")).strip()
        if query:
            cmd.extend(["-q", query])
        patterns_file = str(spearspray_cfg.get("patterns_file", "")).strip()
        if patterns_file:
            cmd.extend(["-i", patterns_file])
        return cmd

    @staticmethod
    def _tail(text: str, limit: int = 8000) -> str:
        text = text or ""
        if len(text) <= limit:
            return text
        return text[-limit:]

    @staticmethod
    def _parse_successes(output: str) -> list[dict]:
        """Best-effort parse for successful credential lines."""
        results: list[dict] = []
        # Typical formats include lines with "valid", "success", or "owned".
        line_pattern = re.compile(
            r"(?i)(valid|success|owned|expired).{0,120}?([a-zA-Z0-9._-]+(?:@[a-zA-Z0-9._-]+)?)[:/ ]+(\S+)"
        )
        for raw_line in (output or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = line_pattern.search(line)
            if not match:
                continue
            username = match.group(2)
            password = match.group(3)
            results.append(
                {
                    "ip": None,
                    "port": 88,
                    "service": "kerberos",
                    "username": username,
                    "password": password,
                    "success": True,
                    "method": "SpearSpray",
                    "raw_line": line,
                }
            )
        return results

    def _store_parsed_results(self, parsed: list[dict], spearspray_cfg: dict) -> list[dict]:
        if not parsed:
            return []

        host_ip = str(spearspray_cfg.get("domain_controller", "")).strip() or "0.0.0.0"
        tested_at = datetime.now(timezone.utc).isoformat()

        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            host_row = conn.execute("SELECT id FROM hosts WHERE ip = ?", (host_ip,)).fetchone()
            if host_row:
                host_id = host_row[0]
            else:
                conn.execute(
                    "INSERT INTO hosts (ip, hostname, first_seen, last_seen, is_active) VALUES (?, ?, ?, ?, 1)",
                    (host_ip, host_ip, tested_at, tested_at),
                )
                host_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            stored: list[dict] = []
            for row in parsed:
                conn.execute(
                    """
                    INSERT INTO credential_results (host_id, port, service, username, credential_hash, success, tested_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?)
                    """,
                    (
                        host_id,
                        int(row.get("port") or 88),
                        str(row.get("service") or "kerberos"),
                        str(row.get("username") or ""),
                        hashlib.sha256(str(row.get("password") or "").encode("utf-8", errors="replace")).hexdigest(),
                        tested_at,
                    ),
                )
                stored.append(
                    {
                        "ip": host_ip,
                        "port": int(row.get("port") or 88),
                        "service": str(row.get("service") or "kerberos"),
                        "username": str(row.get("username") or ""),
                        "password": None,
                        "success": True,
                        "method": "SpearSpray",
                        "timestamp": tested_at,
                    }
                )

            conn.commit()
            return stored
        finally:
            conn.close()
