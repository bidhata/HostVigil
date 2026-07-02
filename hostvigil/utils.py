"""
Shared utility functions for HostVigil.

Provides:
- Stealth file-only logging (no console output to avoid detection)
- Timestamp helpers
- IP address validation
- SQLite database initialization
"""

import ipaddress
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Logging Setup (Stealth - file only, no console handlers)
# ---------------------------------------------------------------------------

def setup_logging(
    log_dir: str | Path = "data/logs",
    log_level: int = logging.INFO,
    log_filename: str = "hostvigil.log",
) -> logging.Logger:
    """Configure stealth file-only logging.

    No console output is produced to minimize detection footprint.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("hostvigil")
    logger.setLevel(log_level)

    # Remove any existing handlers to prevent console leakage
    logger.handlers.clear()
    logger.propagate = False

    # File handler only - stealth mode
    file_handler = logging.FileHandler(
        log_path / log_filename, encoding="utf-8"
    )
    file_handler.setLevel(log_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s.%(funcName)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "hostvigil") -> logging.Logger:
    """Get a child logger under the hostvigil namespace."""
    return logging.getLogger(f"hostvigil.{name}")


# ---------------------------------------------------------------------------
# Timestamp Helpers
# ---------------------------------------------------------------------------

def now_utc() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return now_utc().isoformat()


def timestamp_to_iso(dt: datetime) -> str:
    """Convert a datetime object to ISO 8601 string."""
    return dt.isoformat()


def iso_to_timestamp(iso_str: str) -> datetime:
    """Parse an ISO 8601 string to a datetime object."""
    return datetime.fromisoformat(iso_str)


def elapsed_seconds(start: datetime, end: datetime | None = None) -> float:
    """Calculate elapsed seconds between two timestamps."""
    if end is None:
        end = now_utc()
    return (end - start).total_seconds()


# ---------------------------------------------------------------------------
# IP Address Validation
# ---------------------------------------------------------------------------

def is_valid_ip(address: str) -> bool:
    """Validate an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_valid_network(cidr: str) -> bool:
    """Validate a CIDR network notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_private_ip(address: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def expand_network(cidr: str) -> list[str]:
    """Expand a CIDR network to a list of host IP strings."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(host) for host in network.hosts()]
    except ValueError:
        return []


# ---------------------------------------------------------------------------
# Database Initialization
# ---------------------------------------------------------------------------

_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    mac TEXT,
    hostname TEXT,
    os_fingerprint TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    discovery_method TEXT,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    service TEXT,
    banner TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    hosts_found INTEGER DEFAULT 0,
    ports_found INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port_id INTEGER,
    template_id TEXT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    matched_at TEXT NOT NULL,
    evidence TEXT,
    is_verified INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    anomaly_type TEXT NOT NULL,
    score REAL NOT NULL,
    description TEXT,
    detected_at TEXT NOT NULL,
    is_reviewed INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tls_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    subject TEXT,
    issuer TEXT,
    not_before TEXT,
    not_after TEXT,
    serial_number TEXT,
    fingerprint_sha256 TEXT,
    key_type TEXT,
    key_bits INTEGER,
    san_domains TEXT,
    protocol_version TEXT,
    cipher_suite TEXT,
    is_self_signed INTEGER DEFAULT 0,
    is_expired INTEGER DEFAULT 0,
    inspected_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS service_enum (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER,
    service_type TEXT NOT NULL,
    finding_type TEXT,
    finding TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    title TEXT,
    details TEXT,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS service_enumeration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER,
    service_type TEXT NOT NULL,
    finding_type TEXT,
    severity TEXT DEFAULT 'info',
    title TEXT,
    details TEXT,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ml_training_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trained_at TEXT NOT NULL,
    samples_count INTEGER NOT NULL,
    model_version TEXT NOT NULL,
    accuracy_score REAL
);

CREATE TABLE IF NOT EXISTS host_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    added_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id),
    UNIQUE(host_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_hosts_active ON hosts(is_active);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_ports_active ON ports(is_active);
CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_anomalies_host ON anomalies(host_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_score ON anomalies(score);
CREATE INDEX IF NOT EXISTS idx_host_tags_host ON host_tags(host_id);
CREATE INDEX IF NOT EXISTS idx_host_tags_tag ON host_tags(tag);
"""


def init_database(db_path: str | Path = "data/hostvigil.db") -> sqlite3.Connection:
    """Initialize the SQLite database with the HostVigil schema.

    Creates the database file and parent directories if they don't exist.
    Returns an open connection with WAL mode and foreign keys enabled.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_DB_SCHEMA)
    conn.commit()

    return conn


def get_db_connection(db_path: str | Path = "data/hostvigil.db") -> sqlite3.Connection:
    """Get a database connection with row factory enabled."""
    db_path = Path(db_path)
    if not db_path.exists():
        return init_database(db_path)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def dict_from_row(row: Any) -> dict[str, Any]:
    """Convert a sqlite3.Row to a dictionary."""
    if row is None:
        return {}
    return dict(row)
