import re
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest
import yaml

from hostvigil.config import Config
from hostvigil.dashboard.app import create_app
from hostvigil.dashboard.terminal_guard import parse_and_validate_terminal_command
from hostvigil.export_import import _delete_all_from_table
from hostvigil.orchestrator import HostVigilOrchestrator
from hostvigil.utils import setup_logging


def test_terminal_guard_allows_safe_command():
    parts = parse_and_validate_terminal_command("status --json")
    assert parts == ["status", "--json"]


def test_terminal_guard_blocks_unsafe_command():
    with pytest.raises(PermissionError):
        parse_and_validate_terminal_command("wipe --force")

    with pytest.raises(ValueError):
        parse_and_validate_terminal_command("export --output ../leak.txt")


def test_delete_all_from_table_allowlist():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY, ip TEXT)")
    conn.execute("INSERT INTO hosts (ip) VALUES ('127.0.0.1')")
    conn.commit()

    _delete_all_from_table(conn, "hosts", frozenset({"hosts"}))
    remaining = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    assert remaining == 0

    with pytest.raises(ValueError):
        _delete_all_from_table(conn, "hosts", frozenset({"ports"}))


def test_orchestrator_helper_sanitizers_and_phase_tracking():
    hosts = HostVigilOrchestrator._sanitize_scan_hosts(["10.0.0.1", "not-an-ip", "192.168.1.1"])
    assert hosts == ["10.0.0.1", "192.168.1.1"]

    ports = HostVigilOrchestrator._sanitize_ports_csv("22, 80,invalid,70000,443,22")
    assert ports == "22,80,443"

    orch = HostVigilOrchestrator.__new__(HostVigilOrchestrator)
    orch._shutdown_event = threading.Event()
    orch._stealth_delay = lambda _phase: None
    pipeline = {"phases": {}}

    HostVigilOrchestrator._record_pipeline_phase(orch, pipeline, "scan", {"ports_found": 1})
    assert pipeline["phases"]["scan"]["ports_found"] == 1

    orch._shutdown_event.set()
    with pytest.raises(InterruptedError):
        HostVigilOrchestrator._record_pipeline_phase(orch, pipeline, "scan", {"ports_found": 2})


def test_config_validate_runtime_warns_for_bad_values():
    cfg_data = {
        "hostvigil": {
            "discovery": {"target_ranges": ["192.168.1.0/24"]},
            "scanner": {"naabu": {"rate": -1, "threads": 0}, "ports": {"quick": [22, 99999]}},
            "nuclei": {"rate_limit": -1},
            "dashboard": {"refresh_interval": 0},
            "database": {"path": ""},
            "stealth": {"scan_window_start": 30, "scan_window_end": -1},
        }
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = Path(tmpdir) / "config.yaml"
        cfg_path.write_text(yaml.safe_dump(cfg_data), encoding="utf-8")
        cfg = Config(cfg_path)
        warnings = cfg.validate_runtime()

    assert any("scanner.naabu.rate" in w for w in warnings)
    assert any("scanner.ports.quick" in w for w in warnings)
    assert any("dashboard.refresh_interval" in w for w in warnings)


def _login_as(client, username: str, role: str):
    import time

    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["username"] = username
        sess["role"] = role
        sess["auth_time"] = time.time()
        sess["last_activity"] = time.time()


def _seed_user(conn, username: str, role: str = "admin"):
    from werkzeug.security import generate_password_hash

    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, datetime('now'))",
        (username, generate_password_hash("pass123"), role),
    )
    conn.commit()


def _seed_vulnerability(conn):
    conn.execute(
        "INSERT INTO hosts (ip, first_seen, last_seen, is_active) VALUES ('10.0.0.10', datetime('now'), datetime('now'), 1)"
    )
    host_id = conn.execute("SELECT id FROM hosts WHERE ip='10.0.0.10'").fetchone()[0]
    conn.execute(
        """
        INSERT INTO vulnerabilities (host_id, name, severity, matched_at, status, updated_at)
        VALUES (?, 'Test Vulnerability', 'high', datetime('now'), 'open', datetime('now'))
        """,
        (host_id,),
    )
    conn.commit()
    return conn.execute("SELECT id FROM vulnerabilities ORDER BY id DESC LIMIT 1").fetchone()[0]


def _stop_app_scheduler(app):
    scheduler = getattr(app, "_db_scheduler", None)
    if scheduler:
        scheduler.stop()


def test_rbac_blocks_viewer_write():
    tmpdir = tempfile.mkdtemp(prefix="hv-test-rbac-")
    db_path = Path(tmpdir) / "hv.db"
    app = create_app({"db_path": str(db_path), "db_scheduler_enabled": False})
    client = app.test_client()

    _login_as(client, "viewer1", "viewer")
    resp = client.post("/api/schedule", json={"scan_type": "scan", "cron_expr": "*/5 * * * *"})
    assert resp.status_code == 403
    _stop_app_scheduler(app)


def test_api_token_access_and_lifecycle_workflow():
    tmpdir = tempfile.mkdtemp(prefix="hv-test-token-")
    db_path = Path(tmpdir) / "hv.db"
    app = create_app({"db_path": str(db_path), "db_scheduler_enabled": False})
    client = app.test_client()

    with sqlite3.connect(str(db_path)) as conn:
        _seed_user(conn, "admin2", role="admin")
        vuln_id = _seed_vulnerability(conn)

    _login_as(client, "admin2", "admin")
    token_resp = client.post("/api/auth/tokens", json={"name": "ci-token", "permissions": "read,write"})
    assert token_resp.status_code == 201
    token = token_resp.get_json()["token"]

    # Use API token for read endpoint
    read_resp = client.get("/api/schedule", headers={"X-API-Key": token})
    assert read_resp.status_code == 200

    update_resp = client.post(
        f"/api/vulnerabilities/{vuln_id}/lifecycle",
        json={"status": "in_progress", "owner": "secops", "accepted_risk": False},
        headers={"X-API-Key": token},
    )
    assert update_resp.status_code == 200
    assert update_resp.get_json()["lifecycle"]["status"] == "in_progress"

    comment_resp = client.post(
        f"/api/vulnerabilities/{vuln_id}/comments",
        json={"comment": "triaging this finding"},
        headers={"X-API-Key": token},
    )
    assert comment_resp.status_code == 200
    _stop_app_scheduler(app)


def test_baseline_and_siem_events():
    tmpdir = tempfile.mkdtemp(prefix="hv-test-baseline-")
    db_path = Path(tmpdir) / "hv.db"
    app = create_app({"db_path": str(db_path), "db_scheduler_enabled": False})
    client = app.test_client()

    with sqlite3.connect(str(db_path)) as conn:
        _seed_user(conn, "admin3", role="admin")

    _login_as(client, "admin3", "admin")
    baseline_resp = client.post("/api/baselines", json={"name": "initial", "notes": "first baseline"})
    assert baseline_resp.status_code == 201
    snapshot_id = baseline_resp.get_json()["snapshot_id"]

    drift_resp = client.get(f"/api/baselines/{snapshot_id}/drift")
    assert drift_resp.status_code == 200
    assert "summary" in drift_resp.get_json()

    siem_resp = client.get("/api/siem/events")
    assert siem_resp.status_code == 200
    assert isinstance(siem_resp.get_json().get("events"), list)
    _stop_app_scheduler(app)


def test_credentials_backend_and_job_flow(monkeypatch):
    tmpdir = tempfile.mkdtemp(prefix="hv-test-cred-backend-")
    db_path = Path(tmpdir) / "hv.db"
    app = create_app({"db_path": str(db_path), "db_scheduler_enabled": False})
    client = app.test_client()

    with sqlite3.connect(str(db_path)) as conn:
        _seed_user(conn, "admin4", role="admin")

    _login_as(client, "admin4", "admin")

    backends = client.get("/api/credentials/backends")
    assert backends.status_code == 200
    payload = backends.get_json()
    assert "native" in payload.get("available", [])
    assert "spearspray" in payload.get("available", [])

    from hostvigil.scanner.credential_spray import StealthCredentialSpray

    def _mock_spray_all(self, creds=None, services=None):
        return [
            {
                "ip": "10.0.0.10",
                "port": 22,
                "service": "ssh",
                "username": "admin",
                "success": True,
                "method": "mock-native",
            }
        ]

    monkeypatch.setattr(StealthCredentialSpray, "spray_all", _mock_spray_all)

    start = client.post("/api/credentials/check", json={"backend": "native", "services": ["ssh"]})
    assert start.status_code == 200
    check_id = start.get_json()["check_id"]

    final = None
    for _ in range(40):
        status = client.get(f"/api/credentials/status/{check_id}")
        assert status.status_code == 200
        final = status.get_json()
        if final.get("status") in {"completed", "failed"}:
            break
        time.sleep(0.05)

    assert final is not None
    assert final.get("status") == "completed"
    assert final.get("successes") == 1
    _stop_app_scheduler(app)


def test_credentials_spearspray_ui_config_flow(monkeypatch):
    tmpdir = tempfile.mkdtemp(prefix="hv-test-cred-spearspray-ui-")
    db_path = Path(tmpdir) / "hv.db"
    app = create_app({"db_path": str(db_path), "db_scheduler_enabled": False})
    client = app.test_client()

    with sqlite3.connect(str(db_path)) as conn:
        _seed_user(conn, "admin5", role="admin")

    _login_as(client, "admin5", "admin")

    class _FakeConfig:
        hostvigil = {
            "credential_spray": {
                "backend": "native",
                "enabled": True,
                "timeout_seconds": 1800,
                "native": {"min_delay": 60.0, "max_delay": 120.0, "timeout": 5.0, "jitter_factor": 0.3},
            }
        }

    monkeypatch.setattr("hostvigil.config.get_config", lambda *_args, **_kwargs: _FakeConfig())

    from hostvigil.scanner.spearspray_adapter import SpearSprayAdapter

    def _mock_run(self):
        return {
            "backend": "spearspray",
            "command": ["spearspray"],
            "returncode": 0,
            "stdout_tail": "",
            "stderr_tail": "",
            "results": [
                {
                    "ip": "10.0.0.25",
                    "port": 88,
                    "service": "kerberos",
                    "username": "corp\\admin",
                    "success": True,
                    "method": "SpearSpray",
                }
            ],
            "success_count": 1,
        }

    monkeypatch.setattr(SpearSprayAdapter, "run", _mock_run)

    payload = {
        "backend": "spearspray",
        "services": ["all"],
        "spearspray_config": {
            "binary_path": "spearspray",
            "domain": "corp.example.com",
            "username": "users.txt",
            "password": "passwords.txt",
            "domain_controller": "10.0.0.10",
            "use_ssl": False,
            "threads": "4",
            "jitter": "3,5",
            "max_rps": "",
            "threshold": "2",
            "extra": "",
            "separator": "",
            "suffix": "",
            "query": "",
            "patterns_file": "",
        },
    }

    start = client.post("/api/credentials/check", json=payload)
    assert start.status_code == 200
    check_id = start.get_json()["check_id"]

    final = None
    for _ in range(40):
        status = client.get(f"/api/credentials/status/{check_id}")
        assert status.status_code == 200
        final = status.get_json()
        if final.get("status") in {"completed", "failed"}:
            break
        time.sleep(0.05)

    assert final is not None
    assert final.get("status") == "completed"
    assert final.get("successes") == 1
    assert final.get("backend") == "spearspray"
    _stop_app_scheduler(app)


def test_setup_logging_uses_syslog_style_timestamp():
    with tempfile.TemporaryDirectory(prefix="hv-test-logging-") as tmpdir:
        logger = setup_logging(log_dir=tmpdir, log_filename="hv.log")
        logger.info("syslog-format-check")
        for handler in logger.handlers:
            handler.flush()

        log_file = Path(tmpdir) / "hv.log"
        line = log_file.read_text(encoding="utf-8").strip().splitlines()[-1]
        assert re.match(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z .+ hostvigil\[\d+\] INFO hostvigil syslog-format-check$",
            line,
        )
        for handler in logger.handlers:
            handler.close()
        logger.handlers.clear()
