"""
HostVigil Dashboard - Flask application factory.

Provides both HTML views and JSON API endpoints for network monitoring data.
Binds to 127.0.0.1 only by default (stealth - no network exposure).
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
import sqlite3
import json
import time
import threading
import functools
from pathlib import Path
from contextlib import contextmanager

# Module-level stats cache for _get_stats()
_stats_cache = {'data': None, 'time': 0}
_stats_lock = threading.Lock()


def create_app(config: dict = None):
    """Application factory for the HostVigil dashboard.

    Args:
        config: Optional configuration dictionary. Expected keys:
            - db_path: Path to SQLite database
            - secret_key: Flask secret key
            - refresh_interval: Auto-refresh interval in seconds
    """
    app = Flask(__name__)

    # Default configuration
    app.config.update({
        "DB_PATH": "data/hostvigil.db",
        "SECRET_KEY": "change-this-in-production",
        "REFRESH_INTERVAL": 30,
        "HOST": "127.0.0.1",
        "PORT": 5000,
    })

    # Ensure orchestrator attribute is always defined
    app.orchestrator = None

    # Override with provided config
    if config:
        if "db_path" in config:
            app.config["DB_PATH"] = config["db_path"]
        if "secret_key" in config:
            app.config["SECRET_KEY"] = config["secret_key"]
        if "refresh_interval" in config:
            app.config["REFRESH_INTERVAL"] = config["refresh_interval"]
        if "host" in config:
            app.config["HOST"] = config["host"]
        if "port" in config:
            app.config["PORT"] = config["port"]
        if "orchestrator" in config:
            app.orchestrator = config["orchestrator"]

    # -------------------------------------------------------------------
    # Database helpers
    # -------------------------------------------------------------------

    # Ensure database and tables exist
    from hostvigil.utils import init_database
    init_database(app.config["DB_PATH"])

    # -------------------------------------------------------------------
    # Create additional tables for dashboard features
    # -------------------------------------------------------------------
    def _init_dashboard_tables():
        """Create tables for schedules, profiles, webhooks, notes, users."""
        db_path = Path(app.config["DB_PATH"])
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                cron_expr TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                target_ranges TEXT,
                scan_type TEXT DEFAULT 'full',
                notes TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS webhooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                events TEXT DEFAULT 'all',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        # Create default admin user if not exists
        from werkzeug.security import generate_password_hash
        from datetime import datetime, timezone
        cursor = conn.execute("SELECT id FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            now = datetime.now(timezone.utc).isoformat()
            pw_hash = generate_password_hash("hostvigil")
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                ("admin", pw_hash, now)
            )
        conn.commit()
        conn.close()

    _init_dashboard_tables()

    # -------------------------------------------------------------------
    # Authentication helpers
    # -------------------------------------------------------------------
    def login_required(f):
        """Decorator to require authentication for a route."""
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated_function

    def api_login_required(f):
        """Decorator to require authentication for API endpoints (returns JSON 401)."""
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("logged_in"):
                return jsonify({"error": "Authentication required"}), 401
            return f(*args, **kwargs)
        return decorated_function

    # Scan concurrency: per-type locks allow different operations to run
    # concurrently (e.g. port scan + nuclei at the same time) while preventing
    # duplicate operations of the same type.
    _scan_locks = {}  # {scan_type: threading.Lock()}
    _scan_locks_master = threading.Lock()  # Protects _scan_locks dict creation
    _active_scans = {}  # {scan_type: status_dict}

    # -------------------------------------------------------------------
    # API authentication: require login for all /api/ routes except
    # lightweight polling endpoints (stats, pipeline/live) which are
    # read-only and used by the auto-refresh JS.
    # -------------------------------------------------------------------
    API_PUBLIC_ENDPOINTS = frozenset([
        # Polling endpoints used by dashboard auto-refresh JS (read-only)
        'api_pipeline_live',
        'api_scan_status',
    ])

    @app.before_request
    def _require_api_auth():
        """Enforce authentication on all API endpoints."""
        if request.path.startswith('/api/'):
            # Allow public read-only polling endpoints
            if request.endpoint in API_PUBLIC_ENDPOINTS:
                return None
            # Allow login-related paths
            if request.path == '/api/login':
                return None
            # Require authentication for everything else
            if not session.get("logged_in"):
                return jsonify({"error": "Authentication required"}), 401
        return None

    @contextmanager
    def get_db():
        """Context manager for database connections."""
        db_path = Path(app.config["DB_PATH"])
        conn = sqlite3.connect(str(db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def query_db(sql: str, params: tuple = (), one: bool = False):
        """Execute a query and return results as list of dicts."""
        with get_db() as conn:
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            if one:
                return dict(rows[0]) if rows else None
            return [dict(row) for row in rows]

    # -------------------------------------------------------------------
    # Context processor - inject common data into all templates
    # -------------------------------------------------------------------

    @app.context_processor
    def inject_globals():
        return {
            "refresh_interval": app.config["REFRESH_INTERVAL"],
        }

    # -------------------------------------------------------------------
    # Authentication Routes
    # -------------------------------------------------------------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Login page and form handler."""
        if request.method == "POST":
            from werkzeug.security import check_password_hash
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = query_db(
                "SELECT * FROM users WHERE username = ?", (username,), one=True
            )
            if user and check_password_hash(user["password_hash"], password):
                session["logged_in"] = True
                session["username"] = username
                return redirect(url_for("index"))
            return render_template("login.html", error="Invalid username or password")
        return render_template("login.html", error=None)

    @app.route("/logout")
    def logout():
        """Log out and clear session."""
        session.clear()
        return redirect(url_for("login"))

    # -------------------------------------------------------------------
    # HTML View Routes
    # -------------------------------------------------------------------

    @app.route("/")
    @login_required
    def index():
        """Main dashboard - network overview with stats and charts."""
        stats = _get_stats()
        return render_template("index.html", stats=stats)

    @app.route("/hosts")
    @login_required
    def hosts():
        """Host inventory - JS-powered table fetches from /api/hosts."""
        return render_template("hosts.html")

    @app.route("/vulnerabilities")
    @login_required
    def vulnerabilities():
        """Vulnerability findings from nuclei scans."""
        severity_filter = request.args.get("severity", "").lower()

        sql = """
            SELECT
                v.id,
                v.name,
                v.severity,
                v.template_id,
                v.description,
                v.matched_at,
                v.evidence,
                v.is_verified,
                h.ip,
                h.hostname,
                p.port,
                p.protocol,
                p.service
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
        """
        params = ()

        if severity_filter and severity_filter in ("critical", "high", "medium", "low", "info"):
            sql += " WHERE LOWER(v.severity) = ?"
            params = (severity_filter,)

        sql += " ORDER BY CASE LOWER(v.severity) "
        sql += "   WHEN 'critical' THEN 1 "
        sql += "   WHEN 'high' THEN 2 "
        sql += "   WHEN 'medium' THEN 3 "
        sql += "   WHEN 'low' THEN 4 "
        sql += "   WHEN 'info' THEN 5 "
        sql += "   ELSE 6 END, v.matched_at DESC"

        vuln_data = query_db(sql, params)
        return render_template(
            "vulnerabilities.html",
            vulnerabilities=vuln_data,
            current_filter=severity_filter,
        )

    @app.route("/anomalies")
    @login_required
    def anomalies():
        """ML-detected anomalies view."""
        show_reviewed = request.args.get("show_reviewed", "0") == "1"

        sql = """
            SELECT
                a.id,
                a.anomaly_type,
                a.score,
                a.description,
                a.detected_at,
                a.is_reviewed,
                h.ip,
                h.hostname
            FROM anomalies a
            JOIN hosts h ON h.id = a.host_id
        """

        if not show_reviewed:
            sql += " WHERE a.is_reviewed = 0"

        sql += " ORDER BY a.score DESC, a.detected_at DESC"

        anomaly_data = query_db(sql)
        return render_template(
            "anomalies.html",
            anomalies=anomaly_data,
            show_reviewed=show_reviewed,
        )

    @app.route("/scan-controls")
    @login_required
    def scan_controls():
        """Scan controls - trigger scans and DNS discovery from the dashboard."""
        return render_template("scan_controls.html")

    @app.route("/redteam")
    @login_required
    def redteam():
        """Red team view - exploitable targets grouped by attack vector."""
        # Get verified and high/critical vulns with exploit potential
        exploitable = query_db("""
            SELECT
                v.id,
                v.name,
                v.severity,
                v.template_id,
                v.description,
                v.matched_at,
                v.evidence,
                v.is_verified,
                h.ip,
                h.hostname,
                p.port,
                p.protocol,
                p.service
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
            WHERE LOWER(v.severity) IN ('critical', 'high')
            ORDER BY CASE LOWER(v.severity)
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                ELSE 3 END, v.matched_at DESC
        """)

        # Categorize by attack vector based on template_id and name patterns
        categories = _categorize_exploits(exploitable)

        return render_template("redteam.html", categories=categories)

    # -------------------------------------------------------------------
    # API Endpoints (JSON)
    # -------------------------------------------------------------------

    @app.route("/api/stats")
    def api_stats():
        """API: Get network overview statistics."""
        return jsonify(_get_stats())

    @app.route("/api/hosts")
    def api_hosts():
        """API: Server-side paginated hosts with search, filtering, and sorting.

        Query Parameters:
            page (int): Page number, default 1.
            per_page (int): Results per page, default 50, max 200.
            q (str): Search query (searches ip, hostname, mac, discovery_method).
            subnet (str): Filter by /16 subnet prefix (e.g. '10.82.0.0/16').
            sort (str): Sort column (ip, hostname, port_count, anomaly_count,
                        first_seen, last_seen). Default 'last_seen'.
            order (str): Sort direction (asc, desc). Default 'desc'.
            active_only (str): 'true' (default) or 'false'.

        Returns:
            JSON with hosts list, pagination metadata, and top /16 subnets.
        """
        import ipaddress as _ipaddress
        import math

        # Parse parameters
        page = max(1, request.args.get('page', 1, type=int))
        per_page = min(200, max(1, request.args.get('per_page', 50, type=int)))
        q = request.args.get('q', '').strip()
        subnet_filter = request.args.get('subnet', '').strip()
        sort = request.args.get('sort', 'last_seen')
        order = request.args.get('order', 'desc')
        active_only = request.args.get('active_only', 'true').lower() != 'false'

        # Validate sort/order
        allowed_sorts = {'ip', 'hostname', 'port_count', 'anomaly_count', 'first_seen', 'last_seen'}
        if sort not in allowed_sorts:
            sort = 'last_seen'
        if order not in ('asc', 'desc'):
            order = 'desc'

        # Build the query with subqueries for port_count and anomaly_count
        base_sql = """
            SELECT
                h.id,
                h.ip,
                h.hostname,
                h.mac,
                h.os_fingerprint AS os,
                h.is_active,
                h.discovery_method,
                h.first_seen,
                h.last_seen,
                COALESCE(pc.port_count, 0) AS port_count,
                COALESCE(ac.anomaly_count, 0) AS anomaly_count
            FROM hosts h
            LEFT JOIN (
                SELECT host_id, COUNT(*) AS port_count
                FROM ports WHERE state='open' AND is_active=1
                GROUP BY host_id
            ) pc ON pc.host_id = h.id
            LEFT JOIN (
                SELECT host_id, COUNT(*) AS anomaly_count
                FROM anomalies WHERE is_reviewed=0
                GROUP BY host_id
            ) ac ON ac.host_id = h.id
        """

        where_clauses = []
        params = []

        if active_only:
            where_clauses.append("h.is_active = 1")

        if q:
            where_clauses.append(
                "(h.ip LIKE ? OR h.hostname LIKE ? OR h.mac LIKE ? OR h.discovery_method LIKE ?)"
            )
            like_q = f"%{q}%"
            params.extend([like_q, like_q, like_q, like_q])

        if subnet_filter:
            # Extract the network prefix from the subnet (e.g. '10.82.0.0/16' -> '10.82.')
            try:
                net = _ipaddress.ip_network(subnet_filter, strict=False)
                prefix_len = net.prefixlen
                # For /16, take first 2 octets; for /24, take first 3; for /8, take first 1
                octets_needed = prefix_len // 8
                if octets_needed > 0:
                    prefix = '.'.join(str(net.network_address).split('.')[:octets_needed]) + '.'
                    where_clauses.append("h.ip LIKE ?")
                    params.append(f"{prefix}%")
            except (ValueError, TypeError):
                pass  # Invalid subnet format, ignore filter

        where_sql = ""
        if where_clauses:
            where_sql = " WHERE " + " AND ".join(where_clauses)

        # Sort mapping
        sort_map = {
            'ip': 'h.ip',
            'hostname': 'h.hostname',
            'port_count': 'port_count',
            'anomaly_count': 'anomaly_count',
            'first_seen': 'h.first_seen',
            'last_seen': 'h.last_seen',
        }
        sort_col = sort_map.get(sort, 'h.last_seen')
        order_sql = f" ORDER BY {sort_col} {order.upper()}"

        # Count total matching rows
        count_sql = f"SELECT COUNT(*) AS total FROM hosts h{where_sql}"
        total_row = query_db(count_sql, tuple(params), one=True)
        total = total_row['total'] if total_row else 0
        total_pages = math.ceil(total / per_page) if total > 0 else 0

        # Fetch paginated results
        offset = (page - 1) * per_page
        paginated_sql = base_sql + where_sql + order_sql + " LIMIT ? OFFSET ?"
        hosts_data = query_db(paginated_sql, tuple(params) + (per_page, offset))

        # Build subnet summary (top 20 /16 subnets by host count)
        subnet_sql = """
            SELECT
                SUBSTR(ip, 1, INSTR(ip, '.') + INSTR(SUBSTR(ip, INSTR(ip, '.') + 1), '.')) AS prefix,
                COUNT(*) AS count
            FROM hosts
        """
        if active_only:
            subnet_sql += " WHERE is_active = 1"
        subnet_sql += " GROUP BY prefix ORDER BY count DESC LIMIT 20"

        subnet_rows = query_db(subnet_sql)
        subnets = []
        for row in subnet_rows:
            prefix = row.get('prefix', '')
            if prefix:
                # Convert prefix like '10.82.' to '10.82.0.0/16'
                parts = prefix.rstrip('.').split('.')
                while len(parts) < 4:
                    parts.append('0')
                subnet_cidr = '.'.join(parts[:4]) + '/16'
                subnets.append({'subnet': subnet_cidr, 'count': row['count']})

        return jsonify({
            "hosts": hosts_data,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": total_pages,
            },
            "subnets": subnets,
        })

    @app.route("/api/vulnerabilities")
    def api_vulnerabilities():
        """API: Get all vulnerabilities with optional severity filter."""
        severity_filter = request.args.get("severity", "").lower()

        sql = """
            SELECT
                v.id,
                v.name,
                v.severity,
                v.template_id,
                v.description,
                v.matched_at,
                v.evidence,
                v.is_verified,
                h.ip,
                h.hostname,
                p.port,
                p.protocol,
                p.service
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
        """
        params = ()

        if severity_filter and severity_filter in ("critical", "high", "medium", "low", "info"):
            sql += " WHERE LOWER(v.severity) = ?"
            params = (severity_filter,)

        sql += " ORDER BY CASE LOWER(v.severity) "
        sql += "   WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        sql += "   WHEN 'medium' THEN 3 WHEN 'low' THEN 4 "
        sql += "   WHEN 'info' THEN 5 ELSE 6 END"

        vuln_data = query_db(sql, params)
        return jsonify({"vulnerabilities": vuln_data, "total": len(vuln_data)})

    @app.route("/api/anomalies")
    def api_anomalies():
        """API: Get all anomalies."""
        show_reviewed = request.args.get("show_reviewed", "0") == "1"

        sql = """
            SELECT
                a.id,
                a.anomaly_type,
                a.score,
                a.description,
                a.detected_at,
                a.is_reviewed,
                h.ip,
                h.hostname
            FROM anomalies a
            JOIN hosts h ON h.id = a.host_id
        """

        if not show_reviewed:
            sql += " WHERE a.is_reviewed = 0"

        sql += " ORDER BY a.score DESC, a.detected_at DESC"

        anomaly_data = query_db(sql)
        return jsonify({"anomalies": anomaly_data, "total": len(anomaly_data)})

    @app.route("/api/redteam")
    def api_redteam():
        """API: Get exploitable targets grouped by attack vector."""
        exploitable = query_db("""
            SELECT
                v.id,
                v.name,
                v.severity,
                v.template_id,
                v.description,
                v.matched_at,
                v.evidence,
                v.is_verified,
                h.ip,
                h.hostname,
                p.port,
                p.protocol,
                p.service
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
            WHERE LOWER(v.severity) IN ('critical', 'high')
            ORDER BY v.matched_at DESC
        """)
        categories = _categorize_exploits(exploitable)
        return jsonify({"categories": categories})

    # -------------------------------------------------------------------
    # Scan Trigger API Endpoints
    # -------------------------------------------------------------------

    @app.route("/api/scan/trigger", methods=["POST"])
    @api_login_required
    def api_trigger_scan():
        """Trigger a scan from the dashboard. Runs in background thread.

        Each scan type gets its own lock, so you can run port scan + nuclei
        concurrently. Duplicate operations of the same type are rejected.
        All dashboard-triggered scans run independently of the daemon pipeline.
        """
        scan_type = request.json.get("scan_type", "full") if request.is_json else "full"
        valid_types = ["discover", "scan", "udpscan", "fingerprint", "tls", "enumerate", "analyze", "nuclei", "full"]

        if scan_type not in valid_types:
            return jsonify({"error": f"Invalid scan type. Choose from: {valid_types}"}), 400

        # Get or create a per-type lock
        with _scan_locks_master:
            if scan_type not in _scan_locks:
                _scan_locks[scan_type] = threading.Lock()
            type_lock = _scan_locks[scan_type]

        # Prevent duplicate operations of the same type only
        if not type_lock.acquire(blocking=False):
            return jsonify({
                "error": f"A '{scan_type}' scan is already in progress",
                "status": "busy"
            }), 409

        def _run_scan():
            status_entry = {"type": scan_type, "status": "running", "started": _now_iso()}
            _active_scans[scan_type] = status_entry
            app._scan_running = True
            app._scan_status = status_entry
            try:
                # Always create a fresh orchestrator for dashboard-triggered scans.
                # This ensures scans run immediately and independently of the daemon
                # pipeline cycle (which may be mid-discovery or blocked on slow techniques).
                # SQLite WAL mode supports concurrent access safely.
                from hostvigil.orchestrator import HostVigilOrchestrator
                orch = HostVigilOrchestrator()

                if scan_type == "discover":
                    result = orch.run_discovery()
                elif scan_type == "scan":
                    result = orch.run_scan()
                elif scan_type == "udpscan":
                    result = orch.run_udp_scan()
                elif scan_type == "fingerprint":
                    result = orch.run_os_fingerprint()
                elif scan_type == "tls":
                    result = orch.run_tls_inspection()
                elif scan_type == "enumerate":
                    result = orch.run_service_enum()
                elif scan_type == "analyze":
                    result = orch.run_analysis()
                elif scan_type == "nuclei":
                    result = orch.run_nuclei()
                elif scan_type == "full":
                    result = orch.run_once()
                else:
                    result = {"error": "unknown scan type"}

                completed_status = {
                    "type": scan_type,
                    "status": "completed",
                    "started": status_entry["started"],
                    "completed": _now_iso(),
                    "result": result
                }
                _active_scans[scan_type] = completed_status
                app._scan_status = completed_status
            except Exception as e:
                error_status = {
                    "type": scan_type,
                    "status": "error",
                    "started": status_entry["started"],
                    "error": str(e)
                }
                _active_scans[scan_type] = error_status
                app._scan_status = error_status
            finally:
                app._scan_running = len([s for s in _active_scans.values()
                                         if s.get('status') == 'running']) > 0
                type_lock.release()

        try:
            thread = threading.Thread(target=_run_scan, daemon=True, name=f'scan-{scan_type}')
            thread.start()
        except Exception:
            type_lock.release()
            return jsonify({"error": "Failed to start scan thread"}), 500

        return jsonify({
            "status": "started",
            "scan_type": scan_type,
            "message": f"{scan_type} scan triggered successfully (runs independently of daemon)"
        })

    @app.route("/api/scan/status")
    def api_scan_status():
        """Get current background scan status (all active scans)."""
        running_scans = {k: v for k, v in _active_scans.items()
                        if v.get('status') == 'running'}
        return jsonify({
            "running": len(running_scans) > 0,
            "active_scans": _active_scans,
            "running_types": list(running_scans.keys()),
            # Legacy field for backward compatibility with existing JS
            "scan": getattr(app, '_scan_status', None)
        })

    # -------------------------------------------------------------------
    # Host-level Scan Trigger API
    # -------------------------------------------------------------------

    @app.route('/api/hosts/<ip>/scan', methods=['POST'])
    @api_login_required
    def api_host_scan(ip):
        """Trigger a scan against a single host IP.

        Body (JSON):
            scan_type (str): One of 'scan', 'nuclei', 'fingerprint', 'tls', 'enumerate'.
                             Default 'scan'.

        Runs the operation in a background thread targeting only the specified IP.
        """
        import ipaddress as _ipaddress

        # Validate IP format
        try:
            _ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": f"Invalid IP address: {ip}"}), 400

        scan_type = 'scan'
        if request.is_json and request.json:
            scan_type = request.json.get('scan_type', 'scan')

        valid_types = ['scan', 'nuclei', 'fingerprint', 'tls', 'enumerate']
        if scan_type not in valid_types:
            return jsonify({"error": f"Invalid scan_type. Choose from: {valid_types}"}), 400

        # Check host exists in DB
        host = query_db("SELECT id, ip FROM hosts WHERE ip = ?", (ip,), one=True)
        if not host:
            return jsonify({"error": f"Host {ip} not found in database. Run discovery first."}), 404

        # Track with a unique key per host+type
        scan_key = f"host_{ip}_{scan_type}"

        # Check if already running for this host
        if scan_key in _active_scans and _active_scans[scan_key].get('status') == 'running':
            return jsonify({
                "error": f"A '{scan_type}' scan is already running for {ip}",
                "status": "busy"
            }), 409

        def _run_host_scan():
            status_entry = {
                "type": scan_type,
                "target": ip,
                "status": "running",
                "started": _now_iso(),
            }
            _active_scans[scan_key] = status_entry

            try:
                from hostvigil.orchestrator import HostVigilOrchestrator
                orch = HostVigilOrchestrator()

                if scan_type == 'scan':
                    # TCP port scan against single host
                    from hostvigil.scanner.stealth_scanner import StealthScanner
                    scanner = StealthScanner(orch.config, orch.db_path)
                    result = scanner.scan_hosts([ip])
                elif scan_type == 'fingerprint':
                    from hostvigil.scanner.os_fingerprint import OSFingerprinter
                    fp = OSFingerprinter(orch.config, orch.db_path)
                    result = fp.fingerprint_hosts([ip])
                elif scan_type == 'tls':
                    from hostvigil.scanner.tls_inspector import TLSInspector
                    inspector = TLSInspector(orch.config, orch.db_path)
                    # Get TLS-capable ports for this host
                    tls_ports = query_db(
                        "SELECT port FROM ports WHERE host_id = ? AND state='open' AND port IN (443,636,993,995,465,8443,5986,2376,9443) AND is_active=1",
                        (host['id'],)
                    )
                    targets = [(ip, row['port']) for row in tls_ports]
                    if targets:
                        result = inspector.inspect_targets(targets)
                    else:
                        result = {"message": "No TLS ports found for this host"}
                elif scan_type == 'enumerate':
                    from hostvigil.scanner.service_enum import ServiceEnumerator
                    enumerator = ServiceEnumerator(orch.config, orch.db_path)
                    result = enumerator.enumerate_host(ip)
                elif scan_type == 'nuclei':
                    from hostvigil.nuclei.nuclei_runner import NucleiRunner
                    runner = NucleiRunner(orch.config, orch.db_path)
                    # Build target URLs from open ports
                    open_ports = query_db(
                        "SELECT port, service FROM ports WHERE host_id = ? AND state='open' AND is_active=1",
                        (host['id'],)
                    )
                    targets = []
                    for row in open_ports:
                        port = row['port']
                        service = (row.get('service') or '').lower()
                        if port in (443, 8443, 9443) or 'https' in service:
                            targets.append(f"https://{ip}:{port}")
                        else:
                            targets.append(f"http://{ip}:{port}")
                    if targets:
                        result = runner.run_scan(targets=targets)
                    else:
                        result = {"message": "No open ports found for nuclei scan. Run TCP Scan first."}
                else:
                    result = {"error": "Unknown scan type"}

                _active_scans[scan_key] = {
                    "type": scan_type,
                    "target": ip,
                    "status": "completed",
                    "started": status_entry["started"],
                    "completed": _now_iso(),
                    "result": result,
                }
            except Exception as e:
                _active_scans[scan_key] = {
                    "type": scan_type,
                    "target": ip,
                    "status": "error",
                    "started": status_entry["started"],
                    "error": str(e),
                }

        thread = threading.Thread(target=_run_host_scan, daemon=True, name=f'host-scan-{ip}-{scan_type}')
        thread.start()

        return jsonify({
            "status": "started",
            "scan_type": scan_type,
            "target": ip,
            "message": f"{scan_type} scan triggered for {ip}",
        })

    @app.route("/api/scan/progress")
    def api_scan_progress():
        """API: Real-time progress of all active scans and daemon pipeline status.

        Returns daemon status, dashboard-triggered scan progress, and
        prerequisite readiness for each scan type.
        """
        # --- Daemon status ---
        daemon_info = {"running": False, "current_phase": None, "cycle": 0}
        orch = getattr(app, 'orchestrator', None)
        if orch:
            daemon_info = {
                "running": getattr(orch, 'running', False),
                "current_phase": getattr(orch.status, 'current_phase', None) if hasattr(orch, 'status') else None,
                "cycle": (getattr(orch.status, 'total_runs', 0) if hasattr(orch, 'status') else 0) + 1,
            }

        # --- Dashboard scans progress ---
        dashboard_scans = {}
        scan_types_tracked = ['discover', 'scan', 'udpscan', 'fingerprint', 'tls', 'enumerate', 'analyze', 'nuclei']
        for stype in scan_types_tracked:
            if stype in _active_scans:
                entry = _active_scans[stype]
                dashboard_scans[stype] = {
                    "status": entry.get("status", "idle"),
                    "started": entry.get("started"),
                    "completed": entry.get("completed"),
                    "progress": entry.get("progress"),
                    "error": entry.get("error"),
                }
            else:
                dashboard_scans[stype] = {"status": "idle"}

        # --- Prerequisites: what's ready to scan ---
        def _format_count(count):
            """Format large numbers with comma separator."""
            return f"{count:,}"

        # scan: all active hosts
        scan_count_row = query_db(
            "SELECT COUNT(*) AS cnt FROM hosts WHERE is_active=1", one=True
        )
        scan_count = scan_count_row['cnt'] if scan_count_row else 0

        # nuclei: hosts with open ports
        nuclei_count_row = query_db("""
            SELECT COUNT(DISTINCT h.id) AS cnt
            FROM ports p JOIN hosts h ON p.host_id = h.id
            WHERE p.state='open' AND p.is_active=1 AND h.is_active=1
        """, one=True)
        nuclei_count = nuclei_count_row['cnt'] if nuclei_count_row else 0

        # tls: hosts with TLS-capable ports open
        tls_count_row = query_db("""
            SELECT COUNT(DISTINCT host_id) AS cnt
            FROM ports
            WHERE state='open' AND port IN (443,636,993,995,465,8443,5986,2376,9443) AND is_active=1
        """, one=True)
        tls_count = tls_count_row['cnt'] if tls_count_row else 0

        # enumerate: same as nuclei (needs open ports)
        enumerate_count = nuclei_count

        # fingerprint: same as scan (all active hosts)
        fingerprint_count = scan_count

        # analyze: same as scan (all active hosts)
        analyze_count = scan_count

        prerequisites = {
            "scan": {
                "ready": scan_count > 0,
                "target_count": scan_count,
                "message": f"{_format_count(scan_count)} hosts available" if scan_count > 0 else "No hosts discovered yet. Run Discovery first.",
            },
            "nuclei": {
                "ready": nuclei_count > 0,
                "target_count": nuclei_count,
                "message": f"{_format_count(nuclei_count)} hosts with open ports" if nuclei_count > 0 else "No open ports found. Run TCP Scan first.",
            },
            "fingerprint": {
                "ready": fingerprint_count > 0,
                "target_count": fingerprint_count,
                "message": f"{_format_count(fingerprint_count)} hosts available" if fingerprint_count > 0 else "No hosts discovered yet. Run Discovery first.",
            },
            "tls": {
                "ready": tls_count > 0,
                "target_count": tls_count,
                "message": f"{_format_count(tls_count)} hosts with TLS ports" if tls_count > 0 else "No TLS ports found. Run TCP Scan first.",
            },
            "enumerate": {
                "ready": enumerate_count > 0,
                "target_count": enumerate_count,
                "message": f"{_format_count(enumerate_count)} hosts with services" if enumerate_count > 0 else "No services found. Run TCP Scan first.",
            },
            "analyze": {
                "ready": analyze_count > 0,
                "target_count": analyze_count,
                "message": "Ready" if analyze_count > 0 else "No hosts discovered yet. Run Discovery first.",
            },
        }

        return jsonify({
            "daemon": daemon_info,
            "dashboard_scans": dashboard_scans,
            "prerequisites": prerequisites,
        })

    @app.route("/api/pipeline/status")
    def api_pipeline_status():
        """Get live pipeline status including current phase and last scan details."""
        # Query the scans table for last scan info
        last_scan = query_db(
            "SELECT * FROM scans ORDER BY start_time DESC LIMIT 1", one=True
        )
        recent_scans = query_db(
            "SELECT * FROM scans ORDER BY start_time DESC LIMIT 10"
        )
        stats = _get_stats()

        # Live orchestrator state (available in daemon mode)
        daemon_status = None
        if hasattr(app, 'orchestrator') and app.orchestrator:
            daemon_status = app.orchestrator.get_status()

        return jsonify({
            "last_scan": last_scan,
            "recent_scans": recent_scans,
            "stats": stats,
            "running": getattr(app, '_scan_running', False),
            "current_scan": getattr(app, '_scan_status', None),
            "daemon": daemon_status,
        })

    @app.route("/api/pipeline/live")
    def api_pipeline_live():
        """Lightweight endpoint for polling live updates (stats + daemon state)."""
        stats = _get_stats()
        last_scan = query_db(
            "SELECT * FROM scans ORDER BY start_time DESC LIMIT 1", one=True
        )
        # Detect running: either dashboard-triggered scan OR daemon cycle in progress
        is_running = getattr(app, '_scan_running', False)
        current_phase = None
        daemon_state = None
        total_runs = 0
        total_errors = 0
        hosts_discovered = 0
        ports_found = 0
        last_run_start = None
        last_run_end = None
        last_run_result = None

        if hasattr(app, 'orchestrator') and app.orchestrator:
            orch = app.orchestrator
            # Thread-safe: to_dict() acquires the lock internally
            status_dict = orch.status.to_dict()
            daemon_state = status_dict['state']
            current_phase = status_dict['current_phase']
            total_runs = status_dict['total_runs']
            total_errors = status_dict['total_errors']
            hosts_discovered = status_dict['hosts_discovered']
            ports_found = status_dict['ports_found']
            last_run_start = status_dict['last_run_start']
            last_run_end = status_dict['last_run_end']
            last_run_result = status_dict['last_run_result']
            if daemon_state == 'running' and current_phase:
                is_running = True

        if not is_running and last_scan and not last_scan.get('end_time'):
            is_running = True

        daemon_info = None
        if daemon_state:
            daemon_info = {
                "state": daemon_state,
                "current_phase": current_phase,
                "total_runs": total_runs,
                "total_errors": total_errors,
                "hosts_discovered": hosts_discovered,
                "ports_found": ports_found,
                "last_run_start": last_run_start,
                "last_run_end": last_run_end,
                "last_run_result": last_run_result,
            }
            # FIX #26: Include in_progress_since when a phase is active
            if current_phase is not None:
                daemon_info["in_progress_since"] = last_run_start

        return jsonify({
            "stats": stats,
            "last_scan": last_scan,
            "running": is_running,
            "last_scan_time": last_scan.get('end_time') if last_scan else None,
            "daemon": daemon_info,
        })

    @app.route("/api/anomalies/<int:anomaly_id>/feedback", methods=["POST"])
    def api_anomaly_feedback(anomaly_id):
        """Record operator feedback on an anomaly (true positive or false positive)."""
        from hostvigil.ml_engine.enrichment import MLEnrichmentEngine
        
        if not request.is_json:
            return jsonify({"error": "JSON body required"}), 400
        
        is_tp = request.json.get("is_true_positive", True)
        notes = request.json.get("notes", "")
        
        config = {"model_path": "data/models/"}
        engine = MLEnrichmentEngine(config, app.config["DB_PATH"])
        result = engine.record_feedback(anomaly_id, is_tp, notes)
        
        return jsonify(result)

    @app.route("/api/ml/stats")
    def api_ml_stats():
        """Get ML enrichment engine statistics."""
        from hostvigil.ml_engine.enrichment import MLEnrichmentEngine
        config = {"model_path": "data/models/"}
        engine = MLEnrichmentEngine(config, app.config["DB_PATH"])
        return jsonify(engine.get_enrichment_stats())

    # -------------------------------------------------------------------
    # Host Tagging API Endpoints
    # -------------------------------------------------------------------

    @app.route('/api/hosts/<int:host_id>/tags', methods=['GET'])
    def api_get_host_tags(host_id):
        """API: Get all tags for a host."""
        tags = query_db('SELECT tag, added_at FROM host_tags WHERE host_id = ?', (host_id,))
        return jsonify({'host_id': host_id, 'tags': tags})

    @app.route('/api/hosts/<int:host_id>/tags', methods=['POST'])
    def api_add_host_tag(host_id):
        """API: Add a tag to a host."""
        if not request.is_json:
            return jsonify({'error': 'JSON required'}), 400
        tag = request.json.get('tag', '').strip()
        if not tag:
            return jsonify({'error': 'tag is required'}), 400
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        try:
            with get_db() as conn:
                conn.execute('INSERT OR IGNORE INTO host_tags (host_id, tag, added_at) VALUES (?, ?, ?)', (host_id, tag, now))
                conn.commit()
            return jsonify({'status': 'added', 'host_id': host_id, 'tag': tag})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/hosts/<int:host_id>/tags/<tag>', methods=['DELETE'])
    def api_remove_host_tag(host_id, tag):
        """API: Remove a tag from a host."""
        with get_db() as conn:
            conn.execute('DELETE FROM host_tags WHERE host_id = ? AND tag = ?', (host_id, tag))
            conn.commit()
        return jsonify({'status': 'removed', 'host_id': host_id, 'tag': tag})

    # -------------------------------------------------------------------
    # Scan Diff API Endpoint
    # -------------------------------------------------------------------

    @app.route('/api/diff')
    def api_scan_diff():
        """API: Get network changes over a time window."""
        from hostvigil.scanner.scan_diff import ScanDiff
        hours = request.args.get('hours', 24, type=int)
        diff = ScanDiff(app.config['DB_PATH'])
        return jsonify(diff.get_diff(hours))

    @app.route("/api/discover/dns", methods=["POST"])
    def api_discover_dns():
        """Discover hosts using a custom DNS server for zone transfer or reverse lookups."""
        import threading
        from hostvigil.discovery import StealthDiscovery

        if not request.is_json:
            return jsonify({"error": "JSON body required"}), 400

        dns_server = request.json.get("dns_server", "").strip()
        target_range = request.json.get("target_range", "").strip()
        domain = request.json.get("domain", "").strip()

        if not dns_server:
            return jsonify({"error": "dns_server is required"}), 400

        if hasattr(app, '_scan_running') and app._scan_running:
            return jsonify({"error": "A scan is already in progress", "status": "busy"}), 409

        def _run_dns_discovery():
            import socket
            import sqlite3
            from datetime import datetime, timezone

            app._scan_running = True
            app._scan_status = {"type": "dns_discovery", "status": "running", "started": _now_iso()}
            discovered = []

            try:
                db_path = app.config["DB_PATH"]

                # If target_range provided, do reverse DNS lookups using the custom DNS server
                if target_range:
                    import ipaddress
                    import random
                    import time

                    try:
                        network = ipaddress.ip_network(target_range, strict=False)
                    except ValueError:
                        app._scan_status = {"type": "dns_discovery", "status": "error", "error": "Invalid target_range CIDR"}
                        app._scan_running = False
                        return

                    hosts_list = list(network.hosts())
                    random.shuffle(hosts_list)  # Stealth: randomize order

                    for ip in hosts_list:
                        ip_str = str(ip)
                        try:
                            # Build reverse DNS query using the custom DNS server
                            import struct

                            # Craft DNS PTR query
                            rev_name = '.'.join(reversed(ip_str.split('.'))) + '.in-addr.arpa'
                            query_id = random.randint(0, 65535)

                            # Build DNS packet
                            packet = struct.pack('>HHHHHH', query_id, 0x0100, 1, 0, 0, 0)
                            # Encode domain name
                            for label in rev_name.split('.'):
                                packet += struct.pack('B', len(label)) + label.encode()
                            packet += b'\x00'
                            packet += struct.pack('>HH', 12, 1)  # PTR, IN

                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            sock.settimeout(3.0)
                            sock.sendto(packet, (dns_server, 53))

                            response = sock.recv(1024)
                            sock.close()

                            # Parse response - check if we got an answer
                            if len(response) > 12:
                                answer_count = struct.unpack('>H', response[6:8])[0]
                                if answer_count > 0:
                                    # Extract hostname from response (simplified parsing)
                                    hostname = _parse_dns_ptr_response(response, rev_name)
                                    if hostname:
                                        discovered.append({"ip": ip_str, "hostname": hostname})
                                        _store_dns_host(db_path, ip_str, hostname)

                        except (socket.timeout, OSError):
                            pass

                        # Stealth delay between queries
                        time.sleep(random.uniform(0.5, 2.0))

                # If domain provided, attempt zone transfer (AXFR)
                if domain:
                    import time
                    try:
                        axfr_results = _attempt_zone_transfer(dns_server, domain)
                        for entry in axfr_results:
                            discovered.append(entry)
                            _store_dns_host(db_path, entry["ip"], entry.get("hostname", ""))
                    except Exception:
                        pass

                app._scan_status = {
                    "type": "dns_discovery",
                    "status": "completed",
                    "started": app._scan_status["started"],
                    "completed": _now_iso(),
                    "hosts_found": len(discovered),
                    "results": discovered[:100]  # Limit response size
                }
            except Exception as e:
                app._scan_status = {
                    "type": "dns_discovery",
                    "status": "error",
                    "error": str(e)
                }
            finally:
                app._scan_running = False

        thread = threading.Thread(target=_run_dns_discovery, daemon=True)
        thread.start()

        return jsonify({
            "status": "started",
            "message": f"DNS discovery started using server {dns_server}",
            "dns_server": dns_server,
            "target_range": target_range,
            "domain": domain
        })

    def _now_iso() -> str:
        """Get current UTC time as ISO string."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    def _store_dns_host(db_path: str, ip: str, hostname: str):
        """Store a DNS-discovered host in the database."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
            row = cursor.fetchone()
            if row:
                cursor.execute(
                    "UPDATE hosts SET hostname = ?, last_seen = ?, is_active = 1 WHERE id = ?",
                    (hostname, now, row[0])
                )
            else:
                cursor.execute(
                    "INSERT INTO hosts (ip, hostname, first_seen, last_seen, discovery_method, is_active) "
                    "VALUES (?, ?, ?, ?, 'dns_custom', 1)",
                    (ip, hostname, now, now)
                )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _parse_dns_ptr_response(response: bytes, query_name: str) -> str:
        """Parse a DNS PTR response to extract the hostname."""
        try:
            # Skip header (12 bytes) and question section
            offset = 12
            # Skip question name
            while offset < len(response) and response[offset] != 0:
                if response[offset] & 0xC0 == 0xC0:
                    offset += 2
                    break
                offset += response[offset] + 1
            else:
                offset += 1
            offset += 4  # Skip QTYPE + QCLASS

            # Parse answer section
            if offset >= len(response):
                return ""

            # Skip answer name (may be pointer)
            if response[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(response) and response[offset] != 0:
                    offset += response[offset] + 1
                offset += 1

            if offset + 10 > len(response):
                return ""

            import struct
            rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset+10])
            offset += 10

            if rtype != 12:  # Not PTR
                return ""

            # Read the PTR name
            hostname_parts = []
            end = offset + rdlength
            while offset < end and offset < len(response) and response[offset] != 0:
                if response[offset] & 0xC0 == 0xC0:
                    # Pointer - follow it
                    ptr_offset = struct.unpack('>H', response[offset:offset+2])[0] & 0x3FFF
                    # Read name at pointer
                    while ptr_offset < len(response) and response[ptr_offset] != 0:
                        label_len = response[ptr_offset]
                        if label_len & 0xC0 == 0xC0:
                            break
                        hostname_parts.append(response[ptr_offset+1:ptr_offset+1+label_len].decode('ascii', errors='ignore'))
                        ptr_offset += label_len + 1
                    break
                else:
                    label_len = response[offset]
                    hostname_parts.append(response[offset+1:offset+1+label_len].decode('ascii', errors='ignore'))
                    offset += label_len + 1

            return '.'.join(hostname_parts) if hostname_parts else ""
        except Exception:
            return ""

    def _attempt_zone_transfer(dns_server: str, domain: str) -> list:
        """Attempt DNS zone transfer (AXFR) - often blocked but worth trying."""
        import socket
        import struct

        results = []
        try:
            # Build AXFR query
            query_id = 0x1234
            packet = struct.pack('>HHHHHH', query_id, 0x0000, 1, 0, 0, 0)
            for label in domain.split('.'):
                packet += struct.pack('B', len(label)) + label.encode()
            packet += b'\x00'
            packet += struct.pack('>HH', 252, 1)  # AXFR, IN

            # TCP connection for zone transfer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((dns_server, 53))

            # Send with length prefix (TCP DNS)
            length_prefix = struct.pack('>H', len(packet))
            sock.sendall(length_prefix + packet)

            # Read response
            resp_len_data = sock.recv(2)
            if len(resp_len_data) == 2:
                resp_len = struct.unpack('>H', resp_len_data)[0]
                response = b''
                while len(response) < resp_len:
                    chunk = sock.recv(resp_len - len(response))
                    if not chunk:
                        break
                    response += chunk

                # Parse A records from zone transfer response
                # (simplified - real AXFR parsing is complex)
                if len(response) > 12:
                    answer_count = struct.unpack('>H', response[6:8])[0]
                    if answer_count > 0:
                        # Zone transfer was successful (rare but valuable)
                        pass  # Full AXFR parsing would go here

            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

        return results

    # -------------------------------------------------------------------
    # Export API Endpoints
    # -------------------------------------------------------------------

    @app.route("/api/export/json")
    def api_export_json():
        """API: Export all findings as JSON file download."""
        import os
        from hostvigil.export_import import DataExporter
        from flask import send_file as flask_send_file
        exporter = DataExporter(app.config["DB_PATH"])
        path = os.path.abspath(exporter.export_json())
        return flask_send_file(path, as_attachment=True, download_name=Path(path).name)

    @app.route("/api/export/csv")
    def api_export_csv():
        """API: Export all findings as a ZIP of CSV files."""
        from hostvigil.export_import import DataExporter
        import zipfile
        import io
        from flask import send_file as flask_send_file
        exporter = DataExporter(app.config["DB_PATH"])
        paths = exporter.export_csv()
        # Create zip of all CSVs
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in paths:
                zf.write(p, Path(p).name)
        memory_file.seek(0)
        return flask_send_file(
            memory_file, as_attachment=True,
            download_name="hostvigil_export.zip", mimetype="application/zip"
        )

    @app.route("/api/export/report")
    def api_export_report():
        """API: Generate and download a Markdown summary report."""
        from hostvigil.export_import import DataExporter
        from flask import send_file as flask_send_file
        exporter = DataExporter(app.config["DB_PATH"])
        path = exporter.generate_report()
        return flask_send_file(path, as_attachment=True, download_name=Path(path).name)

    @app.route('/api/export/ips')
    def api_export_ips():
        """API: Export plain IP list (for nmap -iL)."""
        import os
        from hostvigil.c2_export import C2Exporter
        from flask import send_file as flask_send_file
        c2 = C2Exporter(app.config['DB_PATH'])
        path = os.path.abspath(c2.export_ips_only())
        return flask_send_file(path, as_attachment=True, download_name='hostvigil_ips.txt')

    @app.route('/api/export/targets')
    def api_export_targets():
        """API: Export ip:port list (for nuclei -l)."""
        import os
        from hostvigil.c2_export import C2Exporter
        from flask import send_file as flask_send_file
        c2 = C2Exporter(app.config['DB_PATH'])
        path = os.path.abspath(c2.export_targets_txt())
        return flask_send_file(path, as_attachment=True, download_name='hostvigil_targets.txt')

    @app.route('/api/export/urls')
    def api_export_urls():
        """API: Export HTTP URLs (for httpx -l)."""
        import os
        from hostvigil.c2_export import C2Exporter
        from flask import send_file as flask_send_file
        c2 = C2Exporter(app.config['DB_PATH'])
        path = os.path.abspath(c2.export_urls())
        return flask_send_file(path, as_attachment=True, download_name='hostvigil_urls.txt')

    @app.route('/api/export/c2')
    def api_export_c2():
        """API: Export all C2 framework formats (Cobalt Strike/MSF/Sliver/nmap)."""
        from hostvigil.c2_export import C2Exporter
        c2 = C2Exporter(app.config['DB_PATH'])
        results = c2.export_all()
        return jsonify(results)

    @app.route('/api/export/pdf_report')
    def api_export_pdf_report():
        """API: Generate and download a print-ready HTML report."""
        import os
        from hostvigil.report_generator import ReportGenerator
        from flask import send_file as flask_send_file
        gen = ReportGenerator(app.config['DB_PATH'])
        path = os.path.abspath(gen.generate_pdf_report())
        return flask_send_file(path, as_attachment=True, download_name='hostvigil_report.html')

    # -------------------------------------------------------------------
    # Network Graph Endpoints
    # -------------------------------------------------------------------

    @app.route('/network-graph')
    @login_required
    def network_graph():
        return render_template('network_graph.html')

    @app.route('/api/graph/data')
    def api_graph_data():
        """API: Build nodes and edges for the network graph visualization."""
        hosts = query_db('''
            SELECT h.id, h.ip, h.hostname, h.os_fingerprint,
                   COUNT(DISTINCT p.id) as port_count,
                   COUNT(DISTINCT v.id) as vuln_count,
                   MAX(CASE WHEN LOWER(v.severity) = 'critical' THEN 4
                            WHEN LOWER(v.severity) = 'high' THEN 3
                            WHEN LOWER(v.severity) = 'medium' THEN 2
                            ELSE 1 END) as max_severity
            FROM hosts h
            LEFT JOIN ports p ON p.host_id = h.id AND p.is_active = 1
            LEFT JOIN vulnerabilities v ON v.host_id = h.id
            WHERE h.is_active = 1
            GROUP BY h.id
        ''')

        nodes = []
        edges = []
        subnets = {}

        for host in hosts:
            ip = host['ip']
            subnet = '.'.join(ip.split('.')[:3]) + '.0/24'

            severity = host.get('max_severity', 0) or 0
            if severity >= 4:
                color = '#dc3545'
            elif severity >= 3:
                color = '#ff6d00'
            elif severity >= 2:
                color = '#fcb92c'
            else:
                color = '#1cbb8c'

            nodes.append({
                'id': host['id'],
                'label': host.get('hostname') or ip,
                'title': f"{ip}\nPorts: {host['port_count']}\nVulns: {host['vuln_count']}\nOS: {host.get('os_fingerprint') or 'unknown'}",
                'color': color,
                'size': max(10, min(40, 10 + host['port_count'] * 2)),
                'ip': ip,
                'subnet': subnet,
                'port_count': host['port_count'],
                'vuln_count': host['vuln_count'],
            })

            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append(host['id'])

        edge_id = 0
        for subnet, host_ids in subnets.items():
            if len(host_ids) > 1 and len(host_ids) <= 50:
                for i in range(len(host_ids) - 1):
                    edges.append({
                        'id': edge_id,
                        'from': host_ids[i],
                        'to': host_ids[i + 1],
                        'color': {'color': '#2d3748', 'opacity': 0.3},
                    })
                    edge_id += 1

        return jsonify({'nodes': nodes, 'edges': edges, 'subnets': list(subnets.keys())})

    # -------------------------------------------------------------------
    # Attack Paths Endpoints
    # -------------------------------------------------------------------

    @app.route('/attack-paths')
    @login_required
    def attack_paths():
        """Attack path visualization - lateral movement and priv esc chains."""
        return render_template('attack_paths.html')

    @app.route('/api/attack-paths')
    def api_attack_paths():
        """API: Analyze and return attack paths from scan findings."""
        from hostvigil.attack_paths import AttackPathEngine
        engine = AttackPathEngine(app.config['DB_PATH'])
        result = engine.analyze()
        return jsonify(result)

    # -------------------------------------------------------------------
    # Feature: Host Detail Page (Feature 1)
    # -------------------------------------------------------------------

    @app.route('/host/<ip>')
    @login_required
    def host_detail(ip):
        """Host detail page - all info for a single IP."""
        host = query_db("SELECT * FROM hosts WHERE ip = ?", (ip,), one=True)
        if not host:
            return render_template("host_detail.html", host={"ip": ip}, ports=[], vulns=[], tls=[], anomalies=[])

        host_id = host["id"]
        ports = query_db(
            "SELECT * FROM ports WHERE host_id = ? AND is_active = 1 ORDER BY port", (host_id,)
        )
        vulns = query_db("""
            SELECT v.*, p.port, p.protocol FROM vulnerabilities v
            LEFT JOIN ports p ON p.id = v.port_id
            WHERE v.host_id = ? ORDER BY CASE LOWER(v.severity)
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 ELSE 4 END
        """, (host_id,))
        tls = []
        try:
            tls = query_db("SELECT * FROM tls_certificates WHERE host_id = ?", (host_id,))
        except Exception:
            pass  # Table may not exist if TLS inspection hasn't run
        anomalies = query_db(
            "SELECT * FROM anomalies WHERE host_id = ? ORDER BY score DESC", (host_id,)
        )
        return render_template("host_detail.html", host=host, ports=ports, vulns=vulns, tls=tls, anomalies=anomalies)

    # -------------------------------------------------------------------
    # Feature: Session Notes (Feature 6)
    # -------------------------------------------------------------------

    @app.route('/notes', methods=['GET', 'POST'])
    @login_required
    def notes():
        """Session notes - create and view engagement notes."""
        from datetime import datetime, timezone
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()
            if title and content:
                now = datetime.now(timezone.utc).isoformat()
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO notes (title, content, created_at) VALUES (?, ?, ?)",
                        (title, content, now)
                    )
                    conn.commit()
            return redirect(url_for('notes'))

        all_notes = query_db("SELECT * FROM notes ORDER BY created_at DESC")
        return render_template("notes.html", notes=all_notes)

    # -------------------------------------------------------------------
    # Feature: Diff View (Feature 9)
    # -------------------------------------------------------------------

    @app.route('/diff')
    @login_required
    def diff_view():
        """Network diff view - what changed in the last N hours."""
        from datetime import datetime, timezone, timedelta
        hours = request.args.get('hours', 24, type=int)
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        new_hosts = query_db(
            "SELECT * FROM hosts WHERE first_seen >= ? ORDER BY first_seen DESC", (cutoff,)
        )
        new_ports = query_db("""
            SELECT p.*, h.ip FROM ports p
            JOIN hosts h ON h.id = p.host_id
            WHERE p.first_seen >= ? ORDER BY p.first_seen DESC
        """, (cutoff,))
        new_vulns = query_db("""
            SELECT v.*, h.ip, p.port FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
            WHERE v.matched_at >= ? ORDER BY v.matched_at DESC
        """, (cutoff,))

        return render_template("diff.html", new_hosts=new_hosts, new_ports=new_ports,
                               new_vulns=new_vulns, hours=hours)

    # -------------------------------------------------------------------
    # Feature: Scan Scheduling API (Feature 3)
    # -------------------------------------------------------------------

    @app.route('/api/schedule', methods=['GET'])
    def api_get_schedules():
        """API: Get all scan schedules."""
        schedules = query_db("SELECT * FROM schedules ORDER BY created_at DESC")
        return jsonify({"schedules": schedules})

    @app.route('/api/schedule', methods=['POST'])
    def api_add_schedule():
        """API: Add a new scan schedule."""
        from datetime import datetime, timezone
        if not request.is_json:
            return jsonify({"error": "JSON required"}), 400
        scan_type = request.json.get("scan_type", "").strip()
        cron_expr = request.json.get("cron_expr", "").strip()
        enabled = request.json.get("enabled", True)
        if not scan_type or not cron_expr:
            return jsonify({"error": "scan_type and cron_expr are required"}), 400
        now = datetime.now(timezone.utc).isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO schedules (scan_type, cron_expr, enabled, created_at) VALUES (?, ?, ?, ?)",
                (scan_type, cron_expr, 1 if enabled else 0, now)
            )
            conn.commit()
        return jsonify({"status": "created", "scan_type": scan_type, "cron_expr": cron_expr})

    # -------------------------------------------------------------------
    # Feature: Engagement Profiles API (Feature 4)
    # -------------------------------------------------------------------

    @app.route('/api/profiles', methods=['GET'])
    def api_get_profiles():
        """API: Get all engagement profiles."""
        profiles = query_db("SELECT * FROM profiles ORDER BY created_at DESC")
        return jsonify({"profiles": profiles})

    @app.route('/api/profiles', methods=['POST'])
    def api_add_profile():
        """API: Create a new engagement profile."""
        from datetime import datetime, timezone
        if not request.is_json:
            return jsonify({"error": "JSON required"}), 400
        name = request.json.get("name", "").strip()
        if not name:
            return jsonify({"error": "name is required"}), 400
        target_ranges = request.json.get("target_ranges", "")
        scan_type = request.json.get("scan_type", "full")
        notes = request.json.get("notes", "")
        now = datetime.now(timezone.utc).isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO profiles (name, target_ranges, scan_type, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, target_ranges, scan_type, notes, now)
            )
            conn.commit()
        return jsonify({"status": "created", "name": name})

    @app.route('/api/profiles/<int:profile_id>', methods=['DELETE'])
    def api_delete_profile(profile_id):
        """API: Delete an engagement profile."""
        with get_db() as conn:
            conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
            conn.commit()
        return jsonify({"status": "deleted", "id": profile_id})

    # -------------------------------------------------------------------
    # Feature: Webhook Configuration API (Feature 5)
    # -------------------------------------------------------------------

    @app.route('/api/webhooks', methods=['GET'])
    def api_get_webhooks():
        """API: Get all configured webhooks."""
        webhooks = query_db("SELECT * FROM webhooks ORDER BY created_at DESC")
        return jsonify({"webhooks": webhooks})

    @app.route('/api/webhooks', methods=['POST'])
    def api_add_webhook():
        """API: Add a webhook notification endpoint."""
        from datetime import datetime, timezone
        if not request.is_json:
            return jsonify({"error": "JSON required"}), 400
        name = request.json.get("name", "").strip()
        url = request.json.get("url", "").strip()
        events = request.json.get("events", "all")
        if not name or not url:
            return jsonify({"error": "name and url are required"}), 400
        now = datetime.now(timezone.utc).isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO webhooks (name, url, events, created_at) VALUES (?, ?, ?, ?)",
                (name, url, events, now)
            )
            conn.commit()
        return jsonify({"status": "created", "name": name})

    # -------------------------------------------------------------------
    # Feature: Rate Limit Visualization API (Feature 7)
    # -------------------------------------------------------------------

    @app.route('/api/rate-stats')
    def api_rate_stats():
        """API: Get current scan rate/throttle statistics (placeholder)."""
        return jsonify({
            "probes_per_minute": 4.2,
            "avg_delay_seconds": 27.5,
            "backoff_count": 0,
            "decoys_sent": 12,
            "current_jitter": 0.3,
            "rst_detected": 0,
            "throttle_active": False,
            "scan_window_active": True
        })

    # -------------------------------------------------------------------
    # Feature: Export ZIP (Feature 8)
    # -------------------------------------------------------------------

    @app.route('/api/export/zip')
    def api_export_zip():
        """API: Export all findings as a ZIP with JSON + CSV + Markdown."""
        import io
        import zipfile
        import json
        import csv
        from flask import send_file as flask_send_file

        # Gather data
        hosts = query_db("SELECT * FROM hosts")
        ports = query_db("SELECT p.*, h.ip FROM ports p JOIN hosts h ON h.id = p.host_id")
        vulns = query_db("SELECT v.*, h.ip FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id")
        anomalies_data = query_db("SELECT a.*, h.ip FROM anomalies a JOIN hosts h ON h.id = a.host_id")

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
            # JSON export
            export_data = {
                "hosts": hosts,
                "ports": ports,
                "vulnerabilities": vulns,
                "anomalies": anomalies_data,
                "exported_at": _now_iso()
            }
            zf.writestr("hostvigil_export.json", json.dumps(export_data, indent=2, default=str))

            # CSV exports
            if hosts:
                csv_buf = io.StringIO()
                writer = csv.DictWriter(csv_buf, fieldnames=hosts[0].keys())
                writer.writeheader()
                writer.writerows(hosts)
                zf.writestr("hosts.csv", csv_buf.getvalue())

            if ports:
                csv_buf = io.StringIO()
                writer = csv.DictWriter(csv_buf, fieldnames=ports[0].keys())
                writer.writeheader()
                writer.writerows(ports)
                zf.writestr("ports.csv", csv_buf.getvalue())

            if vulns:
                csv_buf = io.StringIO()
                writer = csv.DictWriter(csv_buf, fieldnames=vulns[0].keys())
                writer.writeheader()
                writer.writerows(vulns)
                zf.writestr("vulnerabilities.csv", csv_buf.getvalue())

            # Markdown report
            stats = _get_stats()
            md = f"# HostVigil Report\n\n"
            md += f"**Generated:** {_now_iso()}\n\n"
            md += f"## Summary\n\n"
            md += f"- **Total Hosts:** {stats['total_hosts']}\n"
            md += f"- **Total Ports:** {stats['total_ports']}\n"
            md += f"- **Critical Vulns:** {stats['vulnerabilities']['critical']}\n"
            md += f"- **High Vulns:** {stats['vulnerabilities']['high']}\n"
            md += f"- **Active Anomalies:** {stats['active_anomalies']}\n\n"
            md += f"## Hosts\n\n"
            for h in hosts[:50]:
                md += f"- {h.get('ip', '?')} ({h.get('hostname') or 'unknown'})\n"
            if len(hosts) > 50:
                md += f"\n... and {len(hosts) - 50} more\n"
            md += f"\n## Vulnerabilities\n\n"
            for v in vulns[:50]:
                md += f"- [{v.get('severity', '?').upper()}] {v.get('name', '?')} on {v.get('ip', '?')}\n"
            zf.writestr("report.md", md)

        memory_file.seek(0)
        return flask_send_file(
            memory_file, as_attachment=True,
            download_name="hostvigil_full_export.zip", mimetype="application/zip"
        )

    # -------------------------------------------------------------------
    # Helper Functions
    # -------------------------------------------------------------------

    def _get_stats() -> dict:
        """Gather network overview statistics (cached for 10 seconds)."""
        global _stats_cache
        now = time.time()
        with _stats_lock:
            if _stats_cache['data'] is not None and (now - _stats_cache['time']) < 10:
                return _stats_cache['data']

        total_hosts = query_db(
            "SELECT COUNT(*) as count FROM hosts WHERE is_active = 1", one=True
        )
        total_ports = query_db(
            "SELECT COUNT(*) as count FROM ports WHERE is_active = 1", one=True
        )
        vuln_by_severity = query_db("""
            SELECT LOWER(severity) as severity, COUNT(*) as count
            FROM vulnerabilities
            GROUP BY LOWER(severity)
        """)
        active_anomalies = query_db(
            "SELECT COUNT(*) as count FROM anomalies WHERE is_reviewed = 0",
            one=True,
        )
        recent_scans = query_db(
            "SELECT * FROM scans ORDER BY start_time DESC LIMIT 5"
        )

        # Severity breakdown dict
        severity_counts = {row["severity"]: row["count"] for row in vuln_by_severity}

        result = {
            "total_hosts": total_hosts["count"] if total_hosts else 0,
            "total_ports": total_ports["count"] if total_ports else 0,
            "vulnerabilities": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("info", 0),
                "total": sum(severity_counts.values()),
            },
            "active_anomalies": active_anomalies["count"] if active_anomalies else 0,
            "recent_scans": recent_scans,
        }

        with _stats_lock:
            _stats_cache['data'] = result
            _stats_cache['time'] = now
        return result

    def _categorize_exploits(vulns: list) -> dict:
        """Categorize vulnerabilities by attack vector for red team view."""
        categories = {
            "rce": {"label": "Remote Code Execution", "icon": "💀", "items": []},
            "auth_bypass": {"label": "Authentication Bypass", "icon": "🔓", "items": []},
            "default_creds": {"label": "Default Credentials", "icon": "🔑", "items": []},
            "sqli": {"label": "SQL Injection", "icon": "💉", "items": []},
            "ssrf": {"label": "SSRF / Path Traversal", "icon": "🌐", "items": []},
            "file_inclusion": {"label": "File Inclusion / Upload", "icon": "📁", "items": []},
            "info_disclosure": {"label": "Information Disclosure", "icon": "📋", "items": []},
            "other": {"label": "Other Critical", "icon": "⚡", "items": []},
        }

        for vuln in vulns:
            name_lower = (vuln.get("name") or "").lower()
            template_lower = (vuln.get("template_id") or "").lower()
            combined = f"{name_lower} {template_lower}"

            if any(kw in combined for kw in ["rce", "remote-code", "command-injection", "exec", "deserialization"]):
                categories["rce"]["items"].append(vuln)
            elif any(kw in combined for kw in ["auth-bypass", "authentication-bypass", "unauth", "broken-auth"]):
                categories["auth_bypass"]["items"].append(vuln)
            elif any(kw in combined for kw in ["default-login", "default-cred", "default-password", "weak-password"]):
                categories["default_creds"]["items"].append(vuln)
            elif any(kw in combined for kw in ["sqli", "sql-injection", "sql_injection"]):
                categories["sqli"]["items"].append(vuln)
            elif any(kw in combined for kw in ["ssrf", "path-traversal", "lfi", "directory-traversal"]):
                categories["ssrf"]["items"].append(vuln)
            elif any(kw in combined for kw in ["file-inclusion", "file-upload", "arbitrary-file", "rfi"]):
                categories["file_inclusion"]["items"].append(vuln)
            elif any(kw in combined for kw in ["disclosure", "exposed", "leaked", "sensitive"]):
                categories["info_disclosure"]["items"].append(vuln)
            else:
                categories["other"]["items"].append(vuln)

        # Remove empty categories
        return {k: v for k, v in categories.items() if v["items"]}

    # ===================================================================
    # ADVANCED FEATURES
    # ===================================================================

    # --- Target Tagging (already exists via /api/hosts/<id>/tags) ---
    # Enhanced: filter hosts by tag
    @app.route('/api/hosts/by-tag/<tag>')
    def api_hosts_by_tag(tag):
        """Get all hosts with a specific tag."""
        hosts = query_db('''
            SELECT h.ip, h.hostname, h.mac, h.os_fingerprint, h.is_active,
                   h.first_seen, h.last_seen, h.discovery_method
            FROM hosts h
            JOIN host_tags ht ON ht.host_id = h.id
            WHERE ht.tag = ?
            ORDER BY h.ip
        ''', (tag,))
        return jsonify({'tag': tag, 'hosts': hosts, 'count': len(hosts)})

    @app.route('/api/tags')
    def api_all_tags():
        """Get all unique tags with host counts."""
        tags = query_db('''
            SELECT tag, COUNT(*) as count FROM host_tags GROUP BY tag ORDER BY count DESC
        ''')
        return jsonify(tags)

    # --- Findings Deduplication ---
    @app.route('/api/vulns/grouped')
    def api_vulns_grouped():
        """Group same vulnerability across multiple hosts."""
        grouped = query_db('''
            SELECT v.name, v.severity, v.template_id, COUNT(DISTINCT v.host_id) as host_count,
                   GROUP_CONCAT(DISTINCT h.ip) as affected_hosts
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            GROUP BY v.name, v.severity
            ORDER BY host_count DESC, 
                     CASE LOWER(v.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 
                     WHEN 'medium' THEN 2 ELSE 3 END
        ''')
        return jsonify(grouped)

    # --- Conditional Nuclei Rules ---
    @app.route('/api/nuclei-rules', methods=['GET', 'POST'])
    def api_nuclei_rules():
        """Manage conditional nuclei auto-trigger rules."""
        if request.method == 'POST':
            data = request.get_json()
            if not data or not data.get('condition') or not data.get('template'):
                return jsonify({'error': 'condition and template required'}), 400
            with get_db() as conn:
                conn.execute('''
                    INSERT INTO nuclei_rules (condition_type, condition_value, template_id, enabled, created_at)
                    VALUES (?, ?, ?, 1, datetime('now'))
                ''', (data['condition'], data.get('condition_value', ''), data['template']))
                conn.commit()
            return jsonify({'status': 'created'})
        rules = query_db('SELECT * FROM nuclei_rules ORDER BY created_at DESC')
        return jsonify(rules)

    # --- Banner Change Alerting ---
    @app.route('/api/banner-changes')
    def api_banner_changes():
        """Get recent banner changes detected."""
        changes = query_db('''
            SELECT bc.id, h.ip, h.hostname, bc.port, bc.old_banner, bc.new_banner,
                   bc.detected_at
            FROM banner_changes bc
            JOIN hosts h ON h.id = bc.host_id
            ORDER BY bc.detected_at DESC
            LIMIT 100
        ''')
        return jsonify(changes)

    # --- MITRE ATT&CK Heatmap ---
    @app.route('/mitre')
    @login_required
    def mitre_heatmap():
        """MITRE ATT&CK heatmap page."""
        return render_template('mitre.html')

    @app.route('/api/mitre/coverage')
    def api_mitre_coverage():
        """Get MITRE technique coverage from findings."""
        coverage = query_db('''
            SELECT technique_id, technique_name, tactic, COUNT(*) as evidence_count,
                   MAX(confidence) as max_confidence
            FROM mitre_mappings
            GROUP BY technique_id
            ORDER BY tactic, technique_id
        ''')
        return jsonify(coverage)

    # --- Risk Score Timeline ---
    @app.route('/api/risk-timeline')
    def api_risk_timeline():
        """Get risk score history over time."""
        timeline = query_db('''
            SELECT score, factors, recorded_at
            FROM risk_timeline
            ORDER BY recorded_at ASC
        ''')
        return jsonify(timeline)

    # --- Traffic Budgeting ---
    @app.route('/api/traffic-budget', methods=['GET', 'POST'])
    def api_traffic_budget():
        """Get/set daily packet budget."""
        if request.method == 'POST':
            data = request.get_json()
            budget = data.get('daily_budget', 10000)
            with get_db() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO traffic_budget (id, daily_budget, packets_today, reset_at)
                    VALUES (1, ?, 0, datetime('now'))
                ''', (budget,))
                conn.commit()
            return jsonify({'status': 'updated', 'daily_budget': budget})
        budget = query_db('SELECT * FROM traffic_budget WHERE id = 1', one=True)
        if not budget:
            budget = {'daily_budget': 10000, 'packets_today': 0, 'reset_at': None}
        return jsonify(budget)

    # --- Scan Persona Rotation ---
    @app.route('/api/personas', methods=['GET', 'POST'])
    def api_personas():
        """Manage scan personas (timing/TTL/port profiles)."""
        if request.method == 'POST':
            data = request.get_json()
            with get_db() as conn:
                conn.execute('''
                    INSERT INTO scan_personas (name, config, created_at)
                    VALUES (?, ?, datetime('now'))
                ''', (data.get('name', 'default'), json.dumps(data.get('config', {}))))
                conn.commit()
            return jsonify({'status': 'created'})
        personas = query_db('SELECT * FROM scan_personas ORDER BY created_at DESC')
        return jsonify(personas)

    # --- Credential Correlation Matrix ---
    @app.route('/api/credentials')
    def api_credentials():
        """Get credential correlation matrix."""
        creds = query_db('''
            SELECT c.id, h.ip, h.hostname, c.port, c.service, c.username,
                   c.credential_hash, c.success, c.tested_at
            FROM credential_results c
            JOIN hosts h ON h.id = c.host_id
            WHERE c.success = 1
            ORDER BY c.username, h.ip
        ''')
        return jsonify(creds)

    # --- Honey Token Detection ---
    @app.route('/api/honeytokens')
    def api_honeytokens():
        """Get detected honeypots/canary tokens."""
        tokens = query_db('''
            SELECT ht.id, h.ip, h.hostname, ht.detection_type, ht.confidence,
                   ht.evidence, ht.detected_at
            FROM honeytokens ht
            JOIN hosts h ON h.id = ht.host_id
            ORDER BY ht.confidence DESC
        ''')
        return jsonify(tokens)

    # --- Executive Summary ---
    @app.route('/api/executive-summary')
    def api_executive_summary():
        """Generate executive summary of the engagement."""
        stats = _get_stats()
        vulns = stats.get('vulnerabilities', {})
        
        summary = {
            'engagement_duration': query_db(
                "SELECT MIN(first_seen) as start, MAX(last_seen) as end FROM hosts", one=True
            ),
            'hosts_discovered': stats.get('total_hosts', 0),
            'ports_found': stats.get('total_ports', 0),
            'critical_vulns': vulns.get('critical', 0),
            'high_vulns': vulns.get('high', 0),
            'total_vulns': vulns.get('total', 0),
            'anomalies': stats.get('active_anomalies', 0),
            'attack_paths': len(query_db(
                "SELECT DISTINCT technique_id FROM mitre_mappings WHERE tactic = 'initial-access'"
            )),
            'narrative': _generate_narrative(stats),
        }
        return jsonify(summary)

    def _generate_narrative(stats):
        """Auto-generate attack narrative text."""
        vulns = stats.get('vulnerabilities', {})
        hosts = stats.get('total_hosts', 0)
        critical = vulns.get('critical', 0)
        high = vulns.get('high', 0)
        
        if critical + high == 0:
            return f"Reconnaissance of {hosts} hosts completed. No critical or high severity vulnerabilities identified. The network posture appears strong."
        
        narrative = f"During this engagement, {hosts} hosts were discovered through stealth reconnaissance. "
        if critical > 0:
            narrative += f"{critical} critical vulnerabilities were identified that could allow immediate system compromise. "
        if high > 0:
            narrative += f"{high} high-severity issues provide potential attack paths. "
        narrative += "Detailed findings and recommended remediations are documented in the full report."
        return narrative

    # --- Attack Narrative Generation ---
    @app.route('/api/attack-narrative')
    def api_attack_narrative():
        """Generate attack narrative from findings chain."""
        # Build narrative from scan history + findings
        scans = query_db('SELECT * FROM scans ORDER BY start_time ASC LIMIT 20')
        vulns = query_db('''
            SELECT v.*, h.ip, h.hostname FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            WHERE v.severity IN ('critical', 'high')
            ORDER BY v.matched_at ASC
        ''')
        
        narrative_steps = []
        for scan in scans:
            narrative_steps.append({
                'phase': scan['scan_type'],
                'time': scan['start_time'],
                'result': f"Discovered {scan['hosts_found']} hosts, {scan['ports_found']} ports"
            })
        for vuln in vulns:
            narrative_steps.append({
                'phase': 'exploitation',
                'time': vuln['matched_at'],
                'result': f"{vuln['severity'].upper()}: {vuln['name']} on {vuln['ip']}"
            })
        
        return jsonify({'steps': narrative_steps, 'summary': _generate_narrative(_get_stats())})

    # --- Passive DNS Correlation ---
    @app.route('/api/passive-dns', methods=['GET', 'POST'])
    def api_passive_dns():
        """Store/retrieve passive DNS data."""
        if request.method == 'POST':
            data = request.get_json()
            with get_db() as conn:
                conn.execute('''
                    INSERT OR IGNORE INTO passive_dns (ip, domain, record_type, first_seen, last_seen, source)
                    VALUES (?, ?, ?, datetime('now'), datetime('now'), ?)
                ''', (data.get('ip'), data.get('domain'), data.get('type', 'A'), data.get('source', 'manual')))
                conn.commit()
            return jsonify({'status': 'added'})
        dns_records = query_db('''
            SELECT pd.*, h.hostname as current_hostname
            FROM passive_dns pd
            LEFT JOIN hosts h ON h.ip = pd.ip
            ORDER BY pd.last_seen DESC
            LIMIT 500
        ''')
        return jsonify(dns_records)

    # --- Engagement Comparison ---
    @app.route('/api/compare', methods=['POST'])
    def api_compare_engagement():
        """Compare current findings against imported previous engagement."""
        data = request.get_json()
        previous = data.get('previous', {})
        
        current_hosts = set(r['ip'] for r in query_db('SELECT ip FROM hosts'))
        prev_hosts = set(previous.get('hosts', []))
        
        current_vulns = query_db('SELECT name, severity FROM vulnerabilities')
        prev_vulns = previous.get('vulnerabilities', [])
        prev_vuln_names = set(v.get('name', '') for v in prev_vulns)
        
        comparison = {
            'new_hosts': list(current_hosts - prev_hosts),
            'removed_hosts': list(prev_hosts - current_hosts),
            'common_hosts': len(current_hosts & prev_hosts),
            'new_vulns': [v for v in current_vulns if v['name'] not in prev_vuln_names],
            'resolved_vulns': [v for v in prev_vulns if v.get('name') not in set(cv['name'] for cv in current_vulns)],
            'current_total': len(current_hosts),
            'previous_total': len(prev_hosts),
        }
        return jsonify(comparison)

    # --- Kill Chain Builder ---
    @app.route('/api/kill-chain', methods=['GET', 'POST'])
    def api_kill_chain():
        """Build/retrieve kill chain evidence."""
        if request.method == 'POST':
            data = request.get_json()
            with get_db() as conn:
                conn.execute('''
                    INSERT INTO kill_chain (step_order, title, description, evidence, mitre_id, created_at)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                ''', (data.get('order', 0), data.get('title', ''), 
                      data.get('description', ''), data.get('evidence', ''),
                      data.get('mitre_id', '')))
                conn.commit()
            return jsonify({'status': 'added'})
        chain = query_db('SELECT * FROM kill_chain ORDER BY step_order ASC')
        return jsonify(chain)

    # --- Live Terminal (WebSocket-like via polling) ---
    @app.route('/api/terminal', methods=['POST'])
    @api_login_required
    def api_terminal():
        """Execute a HostVigil CLI command and return output."""
        data = request.get_json()
        cmd = data.get('command', '').strip()

        # Strict allowlist of safe commands with their permitted arguments
        allowed_commands = {
            'status': ['--json'],
            'diff': ['--hours'],
            'export': ['--format', 'json', 'csv', 'report', 'ips', 'targets', 'urls', 'c2'],
        }

        parts = cmd.split()
        if not parts:
            return jsonify({'error': 'No command provided'}), 400

        cmd_base = parts[0]
        if cmd_base not in allowed_commands:
            return jsonify({'error': f'Command not allowed. Permitted: {list(allowed_commands.keys())}'}), 403

        # Validate all arguments against the allowlist for this command
        allowed_args = allowed_commands[cmd_base]
        for arg in parts[1:]:
            # Allow numeric values (e.g., --hours 24)
            if arg.isdigit():
                continue
            if arg not in allowed_args:
                return jsonify({'error': f'Argument not allowed: {arg}'}), 403

        import subprocess
        try:
            # Use list form to prevent shell injection — no shell=True
            result = subprocess.run(
                ['python', 'run.py'] + parts,
                capture_output=True, text=True, timeout=30,
                cwd=str(Path(app.config['DB_PATH']).parent.parent)
            )
            return jsonify({'stdout': result.stdout, 'stderr': result.stderr, 'returncode': result.returncode})
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Command timed out (30s)'}), 408
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # --- Collaborative Mode ---
    @app.route('/api/operators', methods=['GET', 'POST'])
    def api_operators():
        """Track active operators."""
        if request.method == 'POST':
            data = request.get_json()
            with get_db() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO operators (username, last_active, current_page)
                    VALUES (?, datetime('now'), ?)
                ''', (session.get('username', 'anonymous'), data.get('page', '/')))
                conn.commit()
            return jsonify({'status': 'updated'})
        # Return operators active in last 5 minutes
        operators = query_db('''
            SELECT username, last_active, current_page FROM operators
            WHERE last_active > datetime('now', '-5 minutes')
        ''')
        return jsonify(operators)

    # --- Egress Testing ---
    @app.route('/api/egress')
    def api_egress():
        """Get egress test results (passive detection)."""
        results = query_db('''
            SELECT * FROM egress_results ORDER BY tested_at DESC LIMIT 100
        ''')
        return jsonify(results)

    # --- MITRE Heatmap page ---
    # (template created separately)

    # ===================================================================
    # Additional DB Tables for Advanced Features
    # ===================================================================
    def _init_advanced_tables():
        """Create tables for all advanced features."""
        db_path = Path(app.config["DB_PATH"])
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS nuclei_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                condition_type TEXT NOT NULL,
                condition_value TEXT,
                template_id TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS banner_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                old_banner TEXT,
                new_banner TEXT,
                detected_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            );
            CREATE TABLE IF NOT EXISTS mitre_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT NOT NULL,
                technique_name TEXT NOT NULL,
                tactic TEXT NOT NULL,
                confidence REAL DEFAULT 0.5,
                evidence TEXT,
                host_id INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            );
            CREATE TABLE IF NOT EXISTS risk_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                score REAL NOT NULL,
                factors TEXT,
                recorded_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_budget (
                id INTEGER PRIMARY KEY DEFAULT 1,
                daily_budget INTEGER DEFAULT 10000,
                packets_today INTEGER DEFAULT 0,
                reset_at TEXT
            );
            CREATE TABLE IF NOT EXISTS scan_personas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                config TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS credential_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER,
                service TEXT,
                username TEXT,
                credential_hash TEXT,
                success INTEGER DEFAULT 0,
                tested_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            );
            CREATE TABLE IF NOT EXISTS honeytokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                detection_type TEXT NOT NULL,
                confidence REAL DEFAULT 0.5,
                evidence TEXT,
                detected_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            );
            CREATE TABLE IF NOT EXISTS passive_dns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                record_type TEXT DEFAULT 'A',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                source TEXT DEFAULT 'manual',
                UNIQUE(ip, domain, record_type)
            );
            CREATE TABLE IF NOT EXISTS kill_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                step_order INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                mitre_id TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS operators (
                username TEXT PRIMARY KEY,
                last_active TEXT NOT NULL,
                current_page TEXT
            );
            CREATE TABLE IF NOT EXISTS egress_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                dest_port INTEGER,
                protocol TEXT DEFAULT 'tcp',
                success INTEGER DEFAULT 0,
                method TEXT,
                tested_at TEXT NOT NULL
            );
        """)
        conn.commit()
        conn.close()

    _init_advanced_tables()

    return app


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def run_dashboard(config: dict = None):
    """Run the dashboard server (for development/standalone use)."""
    app = create_app(config)
    host = app.config.get("HOST", "127.0.0.1")
    port = app.config.get("PORT", 5000)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run_dashboard()
