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
from typing import Any, Callable


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
    os_confidence REAL DEFAULT 0.0,
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
    host_id INTEGER,
    ip TEXT,
    port INTEGER NOT NULL DEFAULT 443,
    subject TEXT,
    issuer TEXT,
    serial_number TEXT,
    not_before TEXT,
    not_after TEXT,
    is_expired INTEGER DEFAULT 0,
    is_self_signed INTEGER DEFAULT 0,
    signature_algorithm TEXT,
    key_type TEXT,
    key_size INTEGER,
    key_bits INTEGER,
    san_names TEXT,
    san_domains TEXT,
    protocol_version TEXT,
    cipher_suite TEXT,
    cipher_bits INTEGER,
    weaknesses TEXT,
    fingerprint_sha256 TEXT,
    cert_fingerprint_sha256 TEXT,
    weak_cipher INTEGER DEFAULT 0,
    inspected_at TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS service_enumeration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    ip TEXT,
    port INTEGER,
    service_type TEXT,
    finding_type TEXT,
    severity TEXT DEFAULT 'info',
    risk_level TEXT,
    title TEXT,
    details TEXT,
    findings TEXT,
    enum_data TEXT,
    discovered_at TEXT,
    enumerated_at TEXT,
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


# ---------------------------------------------------------------------------
# Schema Migrations
# ---------------------------------------------------------------------------

MigrationFn = Callable[[sqlite3.Connection], None]


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Return True if a column exists on a table."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    """Return True if a table exists."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _ensure_schema_migrations_table(conn: sqlite3.Connection) -> None:
    """Create the migration tracking table if needed."""
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        '''
    )


def _migration_0001_baseline(_conn: sqlite3.Connection) -> None:
    """Baseline marker migration.

    The main schema is still created via _DB_SCHEMA for backward compatibility.
    This migration anchors future incremental migrations.
    """
    return


def _migration_0002_tls_compat(conn: sqlite3.Connection) -> None:
    """Ensure TLS compatibility columns and backfills exist."""
    if not _table_exists(conn, 'tls_certificates'):
        return

    for col_def in (
        'ip TEXT',
        'signature_algorithm TEXT',
        'key_size INTEGER',
        'key_bits INTEGER',
        'san_names TEXT',
        'san_domains TEXT',
        'cipher_bits INTEGER',
        'weaknesses TEXT',
        'fingerprint_sha256 TEXT',
        'cert_fingerprint_sha256 TEXT',
    ):
        col_name = col_def.split()[0]
        if not _column_exists(conn, 'tls_certificates', col_name):
            conn.execute(f'ALTER TABLE tls_certificates ADD COLUMN {col_def}')

    if _column_exists(conn, 'tls_certificates', 'fingerprint_sha256') and _column_exists(conn, 'tls_certificates', 'cert_fingerprint_sha256'):
        conn.execute(
            "UPDATE tls_certificates SET cert_fingerprint_sha256 = fingerprint_sha256 "
            "WHERE (cert_fingerprint_sha256 IS NULL OR cert_fingerprint_sha256 = '') "
            "AND fingerprint_sha256 IS NOT NULL AND fingerprint_sha256 != ''"
        )
        conn.execute(
            "UPDATE tls_certificates SET fingerprint_sha256 = cert_fingerprint_sha256 "
            "WHERE (fingerprint_sha256 IS NULL OR fingerprint_sha256 = '') "
            "AND cert_fingerprint_sha256 IS NOT NULL AND cert_fingerprint_sha256 != ''"
        )

    if _column_exists(conn, 'tls_certificates', 'key_bits') and _column_exists(conn, 'tls_certificates', 'key_size'):
        conn.execute(
            "UPDATE tls_certificates SET key_size = key_bits "
            "WHERE (key_size IS NULL OR key_size = 0) AND key_bits IS NOT NULL AND key_bits > 0"
        )
        conn.execute(
            "UPDATE tls_certificates SET key_bits = key_size "
            "WHERE (key_bits IS NULL OR key_bits = 0) AND key_size IS NOT NULL AND key_size > 0"
        )

    if _column_exists(conn, 'tls_certificates', 'san_domains') and _column_exists(conn, 'tls_certificates', 'san_names'):
        conn.execute(
            "UPDATE tls_certificates SET san_names = san_domains "
            "WHERE (san_names IS NULL OR san_names = '') AND san_domains IS NOT NULL AND san_domains != ''"
        )
        conn.execute(
            "UPDATE tls_certificates SET san_domains = san_names "
            "WHERE (san_domains IS NULL OR san_domains = '') AND san_names IS NOT NULL AND san_names != ''"
        )


def _migration_0003_service_enum_compat(conn: sqlite3.Connection) -> None:
    """Ensure service_enumeration includes modern and legacy-compatible columns."""
    if not _table_exists(conn, 'service_enumeration'):
        conn.execute(
            '''
            CREATE TABLE service_enumeration (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                ip TEXT,
                port INTEGER,
                service_type TEXT,
                finding_type TEXT,
                severity TEXT DEFAULT 'info',
                risk_level TEXT,
                title TEXT,
                details TEXT,
                findings TEXT,
                enum_data TEXT,
                discovered_at TEXT,
                enumerated_at TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
            )
            '''
        )

    for col_def in (
        'ip TEXT',
        'finding_type TEXT',
        "severity TEXT DEFAULT 'info'",
        'risk_level TEXT',
        'title TEXT',
        'details TEXT',
        'findings TEXT',
        'enum_data TEXT',
        'discovered_at TEXT',
        'enumerated_at TEXT',
    ):
        col_name = col_def.split()[0]
        if not _column_exists(conn, 'service_enumeration', col_name):
            conn.execute(f'ALTER TABLE service_enumeration ADD COLUMN {col_def}')


def _migration_0004_credential_results_compat(conn: sqlite3.Connection) -> None:
    """Ensure credential_results canonical schema exists and backfill old names."""
    if not _table_exists(conn, 'credential_results'):
        conn.execute(
            '''
            CREATE TABLE credential_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER,
                service TEXT,
                username TEXT,
                credential_hash TEXT,
                success INTEGER DEFAULT 0,
                tested_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
            )
            '''
        )

    for col_def in (
        'host_id INTEGER',
        'port INTEGER',
        'service TEXT',
        'username TEXT',
        'credential_hash TEXT',
        'success INTEGER DEFAULT 0',
        'tested_at TEXT',
    ):
        col_name = col_def.split()[0]
        if not _column_exists(conn, 'credential_results', col_name):
            conn.execute(f'ALTER TABLE credential_results ADD COLUMN {col_def}')

    if _column_exists(conn, 'credential_results', 'password_hash') and _column_exists(conn, 'credential_results', 'credential_hash'):
        conn.execute(
            "UPDATE credential_results SET credential_hash = password_hash "
            "WHERE (credential_hash IS NULL OR credential_hash = '') AND password_hash IS NOT NULL"
        )
    if _column_exists(conn, 'credential_results', 'attempted_at') and _column_exists(conn, 'credential_results', 'tested_at'):
        conn.execute(
            "UPDATE credential_results SET tested_at = attempted_at "
            "WHERE (tested_at IS NULL OR tested_at = '') AND attempted_at IS NOT NULL"
        )


_MIGRATIONS: list[tuple[str, str, MigrationFn]] = [
    ('0001', 'baseline schema marker', _migration_0001_baseline),
    ('0002', 'tls compatibility columns/backfills', _migration_0002_tls_compat),
    ('0003', 'service enumeration compatibility', _migration_0003_service_enum_compat),
    ('0004', 'credential results compatibility', _migration_0004_credential_results_compat),
]


def run_database_migrations(conn: sqlite3.Connection) -> list[str]:
    """Run pending database migrations in order.

    Returns a list of migration versions applied in this invocation.
    """
    _ensure_schema_migrations_table(conn)
    applied_rows = conn.execute('SELECT version FROM schema_migrations').fetchall()
    applied = {r[0] for r in applied_rows}
    newly_applied: list[str] = []

    for version, description, migration_fn in _MIGRATIONS:
        if version in applied:
            continue

        try:
            migration_fn(conn)
            conn.execute(
                'INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)',
                (version, description, now_iso()),
            )
            newly_applied.append(version)
        except Exception:
            conn.rollback()
            raise

    return newly_applied


def init_database(db_path: str | Path = "data/hostvigil.db") -> sqlite3.Connection:
    """Initialize the SQLite database with the HostVigil schema.

    Creates the database file and parent directories if they don't exist.
    Returns an open connection with WAL mode and foreign keys enabled.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_DB_SCHEMA)
    run_database_migrations(conn)
    conn.commit()

    return conn


def get_db_connection(db_path: str | Path = "data/hostvigil.db") -> sqlite3.Connection:
    """Get a database connection with row factory enabled."""
    db_path = Path(db_path)
    if not db_path.exists():
        return init_database(db_path)

    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    run_database_migrations(conn)
    return conn


def dict_from_row(row: Any) -> dict[str, Any]:
    """Convert a sqlite3.Row to a dictionary."""
    if row is None:
        return {}
    return dict(row)
