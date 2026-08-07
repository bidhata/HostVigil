"""Export API blueprint for the HostVigil dashboard."""

import csv
import io
import json
import os
import tempfile
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from flask import Blueprint, jsonify, request, send_file


def create_export_blueprint(
    db_path_getter: Callable[[], str],
    query_db: Callable,
    get_stats: Callable[[], dict],
    now_iso: Callable[[], str],
) -> Blueprint:
    """Create dashboard export routes with explicit app dependencies."""
    bp = Blueprint("exports", __name__)
    _jobs_lock = threading.Lock()
    _jobs: dict[str, dict] = {}
    _job_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="hv-export-job")

    def _wants_async() -> bool:
        value = (request.args.get("async") or "").strip().lower()
        return value in {"1", "true", "yes"}

    def _submit_job(kind: str, job_func: Callable[[], str]) -> str:
        job_id = uuid.uuid4().hex
        with _jobs_lock:
            _jobs[job_id] = {
                "id": job_id,
                "kind": kind,
                "status": "queued",
                "created_at": now_iso(),
                "started_at": None,
                "finished_at": None,
                "artifact_path": None,
                "error": None,
                "duration_ms": None,
            }

        def _runner():
            start = time.time()
            with _jobs_lock:
                _jobs[job_id]["status"] = "running"
                _jobs[job_id]["started_at"] = now_iso()
            try:
                artifact_path = job_func()
                with _jobs_lock:
                    _jobs[job_id]["status"] = "completed"
                    _jobs[job_id]["artifact_path"] = str(artifact_path)
                    _jobs[job_id]["finished_at"] = now_iso()
                    _jobs[job_id]["duration_ms"] = int((time.time() - start) * 1000)
            except Exception as exc:
                with _jobs_lock:
                    _jobs[job_id]["status"] = "failed"
                    _jobs[job_id]["error"] = str(exc)
                    _jobs[job_id]["finished_at"] = now_iso()
                    _jobs[job_id]["duration_ms"] = int((time.time() - start) * 1000)

        _job_executor.submit(_runner)
        return job_id

    def _build_csv_zip_artifact() -> str:
        from hostvigil.export_import import DataExporter

        exporter = DataExporter(db_path_getter())
        paths = exporter.export_csv()
        fd, zip_path = tempfile.mkstemp(prefix="hostvigil_export_", suffix=".zip")
        os.close(fd)
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for path in paths:
                    zf.write(path, Path(path).name)
        finally:
            for path in paths:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        return zip_path

    def _build_full_zip_artifact() -> str:
        hosts = query_db("SELECT * FROM hosts")
        ports = query_db("SELECT p.*, h.ip FROM ports p JOIN hosts h ON h.id = p.host_id")
        vulns = query_db("SELECT v.*, h.ip FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id")
        anomalies_data = query_db("SELECT a.*, h.ip FROM anomalies a JOIN hosts h ON h.id = a.host_id")

        fd, zip_path = tempfile.mkstemp(prefix="hostvigil_full_export_", suffix=".zip")
        os.close(fd)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            export_data = {
                "hosts": hosts,
                "ports": ports,
                "vulnerabilities": vulns,
                "anomalies": anomalies_data,
                "exported_at": now_iso(),
            }
            zf.writestr("hostvigil_export.json", json.dumps(export_data, indent=2, default=str))

            for name, rows in (
                ("hosts.csv", hosts),
                ("ports.csv", ports),
                ("vulnerabilities.csv", vulns),
            ):
                if not rows:
                    continue
                csv_buf = io.StringIO()
                writer = csv.DictWriter(csv_buf, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
                zf.writestr(name, csv_buf.getvalue())

            stats = get_stats()
            md = "# HostVigil Report\n\n"
            md += f"**Generated:** {now_iso()}\n\n"
            md += "## Summary\n\n"
            md += f"- **Total Hosts:** {stats['total_hosts']}\n"
            md += f"- **Total Ports:** {stats['total_ports']}\n"
            md += f"- **Critical Vulns:** {stats['vulnerabilities']['critical']}\n"
            md += f"- **High Vulns:** {stats['vulnerabilities']['high']}\n"
            md += f"- **Active Anomalies:** {stats['active_anomalies']}\n\n"
            md += "## Hosts\n\n"
            for host in hosts[:50]:
                md += f"- {host.get('ip', '?')} ({host.get('hostname') or 'unknown'})\n"
            if len(hosts) > 50:
                md += f"\n... and {len(hosts) - 50} more\n"
            md += "\n## Vulnerabilities\n\n"
            for vuln in vulns[:50]:
                md += f"- [{vuln.get('severity', '?').upper()}] {vuln.get('name', '?')} on {vuln.get('ip', '?')}\n"
            zf.writestr("report.md", md)
        return zip_path

    @bp.route("/api/jobs/<job_id>")
    def api_job_status(job_id: str):
        with _jobs_lock:
            job = _jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        payload = dict(job)
        if payload.get("artifact_path") and payload.get("status") == "completed":
            payload["artifact_url"] = f"/api/jobs/{job_id}/artifact"
        return jsonify(payload)

    @bp.route("/api/jobs/<job_id>/artifact")
    def api_job_artifact(job_id: str):
        with _jobs_lock:
            job = _jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        if job.get("status") != "completed":
            return jsonify({"error": f"Job is not completed (status={job.get('status')})"}), 409
        artifact_path = job.get("artifact_path")
        if not artifact_path or not os.path.exists(artifact_path):
            return jsonify({"error": "Job artifact not found"}), 404
        return send_file(os.path.abspath(artifact_path), as_attachment=True, download_name=Path(artifact_path).name)

    @bp.route("/api/export/json")
    def api_export_json():
        """Export all findings as a JSON file download."""
        from hostvigil.export_import import DataExporter

        if _wants_async():
            job_id = _submit_job("export_json", lambda: os.path.abspath(DataExporter(db_path_getter()).export_json()))
            return jsonify({"job_id": job_id, "status_url": f"/api/jobs/{job_id}"}), 202

        exporter = DataExporter(db_path_getter())
        path = os.path.abspath(exporter.export_json())
        return send_file(path, as_attachment=True, download_name=Path(path).name)

    @bp.route("/api/export/csv")
    def api_export_csv():
        """Export all findings as a ZIP of CSV files."""
        if _wants_async():
            job_id = _submit_job("export_csv", _build_csv_zip_artifact)
            return jsonify({"job_id": job_id, "status_url": f"/api/jobs/{job_id}"}), 202

        from hostvigil.export_import import DataExporter

        exporter = DataExporter(db_path_getter())
        paths = exporter.export_csv()
        memory_file = io.BytesIO()
        try:
            with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
                for path in paths:
                    zf.write(path, Path(path).name)
        finally:
            # Clean up temporary CSV files
            for path in paths:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        memory_file.seek(0)
        return send_file(
            memory_file,
            as_attachment=True,
            download_name="hostvigil_export.zip",
            mimetype="application/zip",
        )

    @bp.route("/api/export/report")
    def api_export_report():
        """Generate and download a Markdown summary report."""
        from hostvigil.export_import import DataExporter

        if _wants_async():
            job_id = _submit_job(
                "export_report", lambda: os.path.abspath(DataExporter(db_path_getter()).generate_report())
            )
            return jsonify({"job_id": job_id, "status_url": f"/api/jobs/{job_id}"}), 202

        exporter = DataExporter(db_path_getter())
        path = os.path.abspath(exporter.generate_report())
        return send_file(path, as_attachment=True, download_name=Path(path).name)

    @bp.route("/api/export/ips")
    def api_export_ips():
        """Export plain IP list."""
        from hostvigil.c2_export import C2Exporter

        c2 = C2Exporter(db_path_getter())
        path = os.path.abspath(c2.export_ips_only())
        return send_file(path, as_attachment=True, download_name="hostvigil_ips.txt")

    @bp.route("/api/export/targets")
    def api_export_targets():
        """Export ip:port target list."""
        from hostvigil.c2_export import C2Exporter

        c2 = C2Exporter(db_path_getter())
        path = os.path.abspath(c2.export_targets_txt())
        return send_file(path, as_attachment=True, download_name="hostvigil_targets.txt")

    @bp.route("/api/export/urls")
    def api_export_urls():
        """Export HTTP URLs."""
        from hostvigil.c2_export import C2Exporter

        c2 = C2Exporter(db_path_getter())
        path = os.path.abspath(c2.export_urls())
        return send_file(path, as_attachment=True, download_name="hostvigil_urls.txt")

    @bp.route("/api/export/c2")
    def api_export_c2():
        """Export all C2 framework formats."""
        from hostvigil.c2_export import C2Exporter

        return jsonify(C2Exporter(db_path_getter()).export_all())

    @bp.route("/api/export/pivot-paths")
    def api_export_pivot_paths():
        """Export ranked pivot targets and paths."""
        from hostvigil.attack_paths import AttackPathEngine

        analysis = AttackPathEngine(db_path_getter()).analyze()
        return jsonify(
            {
                "best_footholds": analysis.get("best_footholds", []),
                "crown_jewels": analysis.get("crown_jewels", []),
                "pivot_paths": analysis.get("pivot_paths", []),
                "credential_clusters": analysis.get("credential_clusters", []),
                "risk_score": analysis.get("risk_score", 0),
                "summary": analysis.get("summary", ""),
            }
        )

    @bp.route("/api/export/pdf_report")
    def api_export_pdf_report():
        """Generate and download a print-ready HTML report."""
        from hostvigil.report_generator import ReportGenerator

        if _wants_async():
            job_id = _submit_job(
                "export_pdf_report",
                lambda: os.path.abspath(ReportGenerator(db_path_getter()).generate_pdf_report()),
            )
            return jsonify({"job_id": job_id, "status_url": f"/api/jobs/{job_id}"}), 202

        path = os.path.abspath(ReportGenerator(db_path_getter()).generate_pdf_report())
        return send_file(path, as_attachment=True, download_name="hostvigil_report.html")

    @bp.route("/api/export/zip")
    def api_export_zip():
        """Export all findings as a ZIP with JSON + CSV + Markdown."""
        if _wants_async():
            job_id = _submit_job("export_full_zip", _build_full_zip_artifact)
            return jsonify({"job_id": job_id, "status_url": f"/api/jobs/{job_id}"}), 202

        hosts = query_db("SELECT * FROM hosts")
        ports = query_db("SELECT p.*, h.ip FROM ports p JOIN hosts h ON h.id = p.host_id")
        vulns = query_db("SELECT v.*, h.ip FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id")
        anomalies_data = query_db("SELECT a.*, h.ip FROM anomalies a JOIN hosts h ON h.id = a.host_id")

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
            export_data = {
                "hosts": hosts,
                "ports": ports,
                "vulnerabilities": vulns,
                "anomalies": anomalies_data,
                "exported_at": now_iso(),
            }
            zf.writestr("hostvigil_export.json", json.dumps(export_data, indent=2, default=str))

            for name, rows in (
                ("hosts.csv", hosts),
                ("ports.csv", ports),
                ("vulnerabilities.csv", vulns),
            ):
                if not rows:
                    continue
                csv_buf = io.StringIO()
                writer = csv.DictWriter(csv_buf, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
                zf.writestr(name, csv_buf.getvalue())

            stats = get_stats()
            md = "# HostVigil Report\n\n"
            md += f"**Generated:** {now_iso()}\n\n"
            md += "## Summary\n\n"
            md += f"- **Total Hosts:** {stats['total_hosts']}\n"
            md += f"- **Total Ports:** {stats['total_ports']}\n"
            md += f"- **Critical Vulns:** {stats['vulnerabilities']['critical']}\n"
            md += f"- **High Vulns:** {stats['vulnerabilities']['high']}\n"
            md += f"- **Active Anomalies:** {stats['active_anomalies']}\n\n"
            md += "## Hosts\n\n"
            for host in hosts[:50]:
                md += f"- {host.get('ip', '?')} ({host.get('hostname') or 'unknown'})\n"
            if len(hosts) > 50:
                md += f"\n... and {len(hosts) - 50} more\n"
            md += "\n## Vulnerabilities\n\n"
            for vuln in vulns[:50]:
                md += f"- [{vuln.get('severity', '?').upper()}] {vuln.get('name', '?')} on {vuln.get('ip', '?')}\n"
            zf.writestr("report.md", md)

        memory_file.seek(0)
        return send_file(
            memory_file,
            as_attachment=True,
            download_name="hostvigil_full_export.zip",
            mimetype="application/zip",
        )

    return bp
