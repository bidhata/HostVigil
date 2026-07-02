"""
HostVigil Report Generator - Professional HTML reports (print to PDF).

Generates a self-contained HTML file with embedded CSS that can be printed
to PDF from any browser (Ctrl+P / Cmd+P) with professional formatting.
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger('hostvigil.report_generator')


class ReportGenerator:
    """Generate print-ready HTML security assessment reports."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.output_dir = Path('data/reports')
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _query(self, sql: str, params: tuple = ()) -> List[Dict]:
        """Execute query and return list of dicts."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(sql, params)
            rows = [dict(r) for r in cursor.fetchall()]
            return rows
        finally:
            conn.close()

    def _query_one(self, sql: str, params: tuple = ()) -> Optional[Dict]:
        """Execute query and return single dict or None."""
        rows = self._query(sql, params)
        return rows[0] if rows else None

    def _get_stats(self) -> Dict:
        """Gather all statistics for the report."""
        total_hosts = self._query_one("SELECT COUNT(*) as c FROM hosts WHERE is_active = 1")
        total_ports = self._query_one("SELECT COUNT(*) as c FROM ports WHERE is_active = 1")
        total_vulns = self._query_one("SELECT COUNT(*) as c FROM vulnerabilities")
        total_anomalies = self._query_one("SELECT COUNT(*) as c FROM anomalies WHERE is_reviewed = 0")

        severity_counts = {}
        for row in self._query("SELECT LOWER(severity) as sev, COUNT(*) as c FROM vulnerabilities GROUP BY LOWER(severity)"):
            severity_counts[row['sev']] = row['c']

        return {
            'total_hosts': total_hosts['c'] if total_hosts else 0,
            'total_ports': total_ports['c'] if total_ports else 0,
            'total_vulns': total_vulns['c'] if total_vulns else 0,
            'total_anomalies': total_anomalies['c'] if total_anomalies else 0,
            'critical': severity_counts.get('critical', 0),
            'high': severity_counts.get('high', 0),
            'medium': severity_counts.get('medium', 0),
            'low': severity_counts.get('low', 0),
            'info': severity_counts.get('info', 0),
        }

    def _get_hosts(self) -> List[Dict]:
        """Get host inventory."""
        return self._query("""
            SELECT h.ip, h.hostname, h.os_fingerprint, h.first_seen, h.last_seen,
                   h.discovery_method,
                   COUNT(DISTINCT p.id) as port_count,
                   COUNT(DISTINCT v.id) as vuln_count
            FROM hosts h
            LEFT JOIN ports p ON p.host_id = h.id AND p.is_active = 1
            LEFT JOIN vulnerabilities v ON v.host_id = h.id
            WHERE h.is_active = 1
            GROUP BY h.id
            ORDER BY vuln_count DESC, port_count DESC
        """)

    def _get_vulnerabilities(self) -> List[Dict]:
        """Get all vulnerabilities sorted by severity."""
        return self._query("""
            SELECT v.name, v.severity, v.template_id, v.description,
                   v.matched_at, v.is_verified, h.ip, h.hostname, p.port, p.service
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
            ORDER BY CASE LOWER(v.severity)
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 WHEN 'low' THEN 4
                ELSE 5 END
        """)

    def _get_anomalies(self) -> List[Dict]:
        """Get unreviewed anomalies."""
        return self._query("""
            SELECT a.anomaly_type, a.score, a.description, a.detected_at,
                   h.ip, h.hostname
            FROM anomalies a
            JOIN hosts h ON h.id = a.host_id
            WHERE a.is_reviewed = 0
            ORDER BY a.score DESC
            LIMIT 50
        """)

    def _calculate_risk_score(self, stats: Dict) -> int:
        """Calculate overall risk score 0-100."""
        score = 0
        score += min(stats['critical'] * 20, 40)
        score += min(stats['high'] * 10, 30)
        score += min(stats['medium'] * 3, 15)
        score += min(stats['low'] * 1, 5)
        score += min(stats['total_anomalies'] * 2, 10)
        return min(score, 100)

    def _risk_label(self, score: int) -> str:
        """Get risk label from score."""
        if score >= 75:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _risk_color(self, score: int) -> str:
        """Get color for risk score."""
        if score >= 75:
            return '#dc3545'
        elif score >= 50:
            return '#ff6d00'
        elif score >= 25:
            return '#fcb92c'
        else:
            return '#1cbb8c'

    def _severity_badge(self, severity: str) -> str:
        """Generate HTML badge for severity level."""
        colors = {
            'critical': '#dc3545', 'high': '#ff6d00',
            'medium': '#fcb92c', 'low': '#17a2b8', 'info': '#6c757d'
        }
        color = colors.get((severity or '').lower(), '#6c757d')
        return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;font-size:0.75rem;font-weight:600;">{(severity or "unknown").upper()}</span>'

    def _donut_svg(self, stats: Dict) -> str:
        """Generate inline SVG donut chart for severity breakdown."""
        values = [
            (stats['critical'], '#dc3545', 'Critical'),
            (stats['high'], '#ff6d00', 'High'),
            (stats['medium'], '#fcb92c', 'Medium'),
            (stats['low'], '#17a2b8', 'Low'),
            (stats['info'], '#6c757d', 'Info'),
        ]
        total = sum(v[0] for v in values)
        if total == 0:
            return '<svg width="200" height="200"><circle cx="100" cy="100" r="70" fill="none" stroke="#333" stroke-width="30"/><text x="100" y="105" text-anchor="middle" fill="#666" font-size="14">No vulns</text></svg>'

        svg_parts = ['<svg width="200" height="200" viewBox="0 0 200 200">']
        offset = 0
        cx, cy, r = 100, 100, 70
        circumference = 2 * 3.14159 * r

        for count, color, label in values:
            if count == 0:
                continue
            dash = (count / total) * circumference
            gap = circumference - dash
            svg_parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="{color}" stroke-width="30" '
                f'stroke-dasharray="{dash:.1f} {gap:.1f}" '
                f'stroke-dashoffset="{-offset:.1f}" '
                f'transform="rotate(-90 {cx} {cy})"/>'
            )
            offset += dash

        svg_parts.append(f'<text x="100" y="95" text-anchor="middle" fill="#333" font-size="24" font-weight="bold">{total}</text>')
        svg_parts.append('<text x="100" y="115" text-anchor="middle" fill="#666" font-size="11">Total Findings</text>')
        svg_parts.append('</svg>')
        return ''.join(svg_parts)

    def generate_pdf_report(self, output_path: str = None) -> str:
        """Generate a print-ready HTML report.

        Args:
            output_path: Optional output file path. If None, auto-generates.

        Returns:
            Path to the generated HTML file.
        """
        timestamp = datetime.now(timezone.utc)
        stats = self._get_stats()
        hosts = self._get_hosts()
        vulns = self._get_vulnerabilities()
        anomalies = self._get_anomalies()
        risk_score = self._calculate_risk_score(stats)
        risk_label = self._risk_label(risk_score)
        risk_color = self._risk_color(risk_score)

        if output_path is None:
            fname = f"hostvigil_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.html"
            output_path = str(self.output_dir / fname)

        html = self._build_html(
            timestamp=timestamp,
            stats=stats,
            hosts=hosts,
            vulns=vulns,
            anomalies=anomalies,
            risk_score=risk_score,
            risk_label=risk_label,
            risk_color=risk_color,
        )

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(html, encoding='utf-8')
        logger.info(f'Report generated: {output_path}')
        return output_path

    def _build_html(self, **ctx) -> str:
        """Build the full HTML report."""
        timestamp = ctx['timestamp']
        stats = ctx['stats']
        hosts = ctx['hosts']
        vulns = ctx['vulns']
        anomalies = ctx['anomalies']
        risk_score = ctx['risk_score']
        risk_label = ctx['risk_label']
        risk_color = ctx['risk_color']

        # Build vulnerability table rows
        vuln_rows = ''
        for v in vulns[:100]:
            target = v.get('hostname') or v['ip']
            port_info = f":{v['port']}" if v.get('port') else ''
            vuln_rows += f"""<tr>
                <td>{self._severity_badge(v['severity'])}</td>
                <td>{_esc(v['name'])}</td>
                <td><code>{_esc(target)}{port_info}</code></td>
                <td>{_esc(v.get('service') or '-')}</td>
                <td>{_esc(v.get('matched_at') or '-')}</td>
            </tr>\n"""

        # Build host table rows
        host_rows = ''
        for h in hosts[:100]:
            host_rows += f"""<tr>
                <td><code>{_esc(h['ip'])}</code></td>
                <td>{_esc(h.get('hostname') or '-')}</td>
                <td>{_esc(h.get('os_fingerprint') or '-')}</td>
                <td>{h['port_count']}</td>
                <td>{h['vuln_count']}</td>
                <td>{_esc(h.get('discovery_method') or '-')}</td>
            </tr>\n"""

        # Build anomaly table rows
        anomaly_rows = ''
        for a in anomalies[:50]:
            anomaly_rows += f"""<tr>
                <td><code>{_esc(a.get('hostname') or a['ip'])}</code></td>
                <td>{_esc(a['anomaly_type'])}</td>
                <td><strong>{a['score']:.2f}</strong></td>
                <td>{_esc(a['description'])}</td>
                <td>{_esc(a.get('detected_at') or '-')}</td>
            </tr>\n"""

        donut_svg = self._donut_svg(stats)
        gen_time = timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HostVigil Security Assessment Report</title>
<style>
{_get_report_css()}
</style>
</head>
<body>
<div class="report">

<!-- Cover / Header -->
<div class="report-header">
    <h1>Security Assessment Report</h1>
    <p class="subtitle">HostVigil Internal Network Reconnaissance</p>
    <p class="gen-date">Generated: {gen_time}</p>
</div>

<!-- Table of Contents -->
<div class="toc page-break-after">
    <h2>Table of Contents</h2>
    <ol>
        <li><a href="#executive-summary">Executive Summary</a></li>
        <li><a href="#network-overview">Network Overview</a></li>
        <li><a href="#vulnerability-findings">Vulnerability Findings</a></li>
        <li><a href="#host-inventory">Host Inventory</a></li>
        <li><a href="#anomaly-detection">Anomaly Detection</a></li>
        <li><a href="#recommendations">Recommendations</a></li>
        <li><a href="#methodology">Methodology</a></li>
    </ol>
</div>

<!-- Executive Summary -->
<div class="section page-break-before" id="executive-summary">
    <h2>1. Executive Summary</h2>
    <div class="risk-box" style="border-left: 4px solid {risk_color};">
        <div class="risk-score-display">
            <div class="risk-number" style="color: {risk_color};">{risk_score}</div>
            <div class="risk-label">Overall Risk: <strong style="color:{risk_color};">{risk_label}</strong></div>
        </div>
        <p>This assessment identified <strong>{stats['total_hosts']}</strong> active hosts with
        <strong>{stats['total_ports']}</strong> open ports. A total of <strong>{stats['total_vulns']}</strong>
        vulnerabilities were discovered, including <strong style="color:#dc3545;">{stats['critical']} critical</strong>
        and <strong style="color:#ff6d00;">{stats['high']} high</strong> severity findings.
        The ML engine flagged <strong>{stats['total_anomalies']}</strong> unreviewed anomalies.</p>
    </div>

    <div class="summary-grid">
        <div class="summary-card">
            <div class="card-number">{stats['total_hosts']}</div>
            <div class="card-label">Active Hosts</div>
        </div>
        <div class="summary-card">
            <div class="card-number">{stats['total_ports']}</div>
            <div class="card-label">Open Ports</div>
        </div>
        <div class="summary-card">
            <div class="card-number" style="color:#dc3545;">{stats['critical']}</div>
            <div class="card-label">Critical Vulns</div>
        </div>
        <div class="summary-card">
            <div class="card-number" style="color:#ff6d00;">{stats['high']}</div>
            <div class="card-label">High Vulns</div>
        </div>
    </div>
</div>

<!-- Network Overview -->
<div class="section page-break-before" id="network-overview">
    <h2>2. Network Overview</h2>
    <div class="chart-container">
        <div class="chart-svg">{donut_svg}</div>
        <div class="chart-legend">
            <div class="legend-row"><span class="ldot" style="background:#dc3545;"></span> Critical: {stats['critical']}</div>
            <div class="legend-row"><span class="ldot" style="background:#ff6d00;"></span> High: {stats['high']}</div>
            <div class="legend-row"><span class="ldot" style="background:#fcb92c;"></span> Medium: {stats['medium']}</div>
            <div class="legend-row"><span class="ldot" style="background:#17a2b8;"></span> Low: {stats['low']}</div>
            <div class="legend-row"><span class="ldot" style="background:#6c757d;"></span> Info: {stats['info']}</div>
        </div>
    </div>
</div>

<!-- Vulnerability Findings -->
<div class="section page-break-before" id="vulnerability-findings">
    <h2>3. Vulnerability Findings</h2>
    <p>Total: <strong>{stats['total_vulns']}</strong> findings across all severity levels.</p>
    <table>
        <thead><tr><th>Severity</th><th>Name</th><th>Target</th><th>Service</th><th>Detected</th></tr></thead>
        <tbody>{vuln_rows if vuln_rows else '<tr><td colspan="5" class="empty">No vulnerabilities found</td></tr>'}</tbody>
    </table>
</div>

<!-- Host Inventory -->
<div class="section page-break-before" id="host-inventory">
    <h2>4. Host Inventory</h2>
    <p>Total active hosts: <strong>{stats['total_hosts']}</strong></p>
    <table>
        <thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Vulns</th><th>Discovery</th></tr></thead>
        <tbody>{host_rows if host_rows else '<tr><td colspan="6" class="empty">No hosts discovered</td></tr>'}</tbody>
    </table>
</div>

<!-- Anomaly Detection -->
<div class="section page-break-before" id="anomaly-detection">
    <h2>5. Anomaly Detection</h2>
    <p>Unreviewed ML-detected anomalies: <strong>{stats['total_anomalies']}</strong></p>
    <table>
        <thead><tr><th>Host</th><th>Type</th><th>Score</th><th>Description</th><th>Detected</th></tr></thead>
        <tbody>{anomaly_rows if anomaly_rows else '<tr><td colspan="5" class="empty">No anomalies detected</td></tr>'}</tbody>
    </table>
</div>

<!-- Recommendations -->
<div class="section page-break-before" id="recommendations">
    <h2>6. Recommendations</h2>
    <ol class="recommendations">
        {"<li><strong>Immediate:</strong> Remediate all critical vulnerabilities. These represent active exploitation risk.</li>" if stats['critical'] > 0 else ""}
        {"<li><strong>High Priority:</strong> Address high-severity findings within 7 days.</li>" if stats['high'] > 0 else ""}
        {"<li><strong>Review Anomalies:</strong> Investigate ML-flagged anomalies for potential compromise indicators.</li>" if stats['total_anomalies'] > 0 else ""}
        <li><strong>Network Segmentation:</strong> Ensure proper segmentation between discovered subnets.</li>
        <li><strong>Patch Management:</strong> Implement regular patching for all discovered services.</li>
        <li><strong>Access Controls:</strong> Verify authentication is enforced on all exposed services.</li>
        <li><strong>Monitoring:</strong> Deploy continuous monitoring for the identified hosts.</li>
    </ol>
</div>

<!-- Methodology -->
<div class="section page-break-before" id="methodology">
    <h2>7. Methodology</h2>
    <p>This assessment was conducted using HostVigil's stealth reconnaissance platform with the following techniques:</p>
    <ul>
        <li><strong>Discovery:</strong> ARP sweep, passive sniffing, mDNS, NetBIOS, DNS reverse walk, SNMP, SSDP, TCP SYN, DHCP passive</li>
        <li><strong>Scanning:</strong> TCP connect/SYN, UDP probes, OS fingerprinting, TLS inspection, service enumeration</li>
        <li><strong>Analysis:</strong> ML-based anomaly detection (Isolation Forest), temporal baseline, service correlation</li>
        <li><strong>Vulnerability Assessment:</strong> Nuclei templates (rate-limited, stealth configuration)</li>
    </ul>
    <p>All scanning was performed with stealth timing (randomized delays, adaptive throttling) to minimize detection risk.</p>
</div>

</div>

<div class="report-footer">
    <p>Generated by HostVigil | {gen_time} | Confidential</p>
    <p class="print-hint"><em>To save as PDF: File &rarr; Print &rarr; Save as PDF (or Ctrl+P)</em></p>
</div>

</body>
</html>"""


def _esc(text) -> str:
    """HTML-escape a string."""
    if text is None:
        return ''
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def _get_report_css() -> str:
    """Return embedded CSS for the report."""
    return """
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #1a1a2e;
    background: #fff;
    padding: 20px;
}
.report { max-width: 900px; margin: 0 auto; }
.report-header {
    text-align: center;
    padding: 60px 20px 40px;
    border-bottom: 3px solid #1a1a2e;
    margin-bottom: 30px;
}
.report-header h1 { font-size: 28pt; margin-bottom: 8px; color: #1a1a2e; }
.report-header .subtitle { font-size: 14pt; color: #555; margin-bottom: 4px; }
.report-header .gen-date { font-size: 10pt; color: #888; }
.toc { padding: 20px 0; }
.toc h2 { margin-bottom: 16px; }
.toc ol { padding-left: 24px; }
.toc li { margin-bottom: 6px; }
.toc a { color: #1a73e8; text-decoration: none; }
.section { padding: 20px 0; }
.section h2 {
    font-size: 16pt;
    color: #1a1a2e;
    border-bottom: 2px solid #e0e0e0;
    padding-bottom: 8px;
    margin-bottom: 16px;
}
.risk-box {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 6px;
    margin-bottom: 20px;
}
.risk-score-display { display: flex; align-items: center; gap: 16px; margin-bottom: 12px; }
.risk-number { font-size: 48pt; font-weight: 700; line-height: 1; }
.risk-label { font-size: 14pt; }
.summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 20px; }
.summary-card {
    text-align: center;
    padding: 16px;
    background: #f8f9fa;
    border-radius: 6px;
    border: 1px solid #e0e0e0;
}
.card-number { font-size: 24pt; font-weight: 700; }
.card-label { font-size: 9pt; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
.chart-container { display: flex; align-items: center; gap: 30px; padding: 20px 0; }
.chart-legend { font-size: 10pt; }
.legend-row { display: flex; align-items: center; margin-bottom: 6px; }
.ldot { width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; display: inline-block; }
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 9pt;
    margin-top: 12px;
}
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #e0e0e0; }
th { background: #f0f0f0; font-weight: 600; font-size: 8pt; text-transform: uppercase; letter-spacing: 0.3px; }
tr:nth-child(even) { background: #fafafa; }
td.empty { text-align: center; color: #888; font-style: italic; padding: 20px; }
code { background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 9pt; }
.recommendations li { margin-bottom: 10px; }
.report-footer {
    margin-top: 40px;
    padding-top: 16px;
    border-top: 1px solid #e0e0e0;
    text-align: center;
    font-size: 9pt;
    color: #888;
}
.print-hint { margin-top: 8px; }

/* Print styles */
@media print {
    body { padding: 0; font-size: 10pt; }
    .report { max-width: 100%; }
    .page-break-before { page-break-before: always; }
    .page-break-after { page-break-after: always; }
    .print-hint { display: none; }
    .report-header { padding: 40px 0 30px; }
    table { page-break-inside: auto; }
    tr { page-break-inside: avoid; }
    .summary-grid { grid-template-columns: repeat(4, 1fr); }
}
"""
