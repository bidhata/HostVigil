"""
HostVigil Orchestrator - Coordinates all scanning and analysis modules.

Manages the full reconnaissance pipeline:
  Discovery -> Scan -> ML Analysis -> Nuclei (conditional) -> Dashboard

Supports single-run mode, individual module execution, and continuous
daemon mode with configurable scheduling and stealth timing.
"""

import os
import signal
import sqlite3
import logging
import threading
import random
from pathlib import Path
from typing import Optional

from hostvigil.config import Config
from hostvigil.utils import setup_logging, init_database, now_iso, get_db_connection
from hostvigil.discovery import StealthDiscovery
from hostvigil.scanner import StealthScanner
from hostvigil.scanner.os_fingerprint import OSFingerprinter
from hostvigil.scanner.tls_inspector import TLSInspector
from hostvigil.scanner.service_enum import ServiceEnumerator
from hostvigil.ml_engine import AnomalyDetector
from hostvigil.ml_engine.enrichment import MLEnrichmentEngine
from hostvigil.nuclei import NucleiRunner
from hostvigil.dashboard import create_app

logger = logging.getLogger('hostvigil.orchestrator')


class PipelineStatus:
    """Tracks pipeline execution state for status reporting."""

    def __init__(self):
        self.state: str = 'idle'
        self.current_phase: Optional[str] = None
        self.last_run_start: Optional[str] = None
        self.last_run_end: Optional[str] = None
        self.last_run_result: Optional[str] = None
        self.total_runs: int = 0
        self.total_errors: int = 0
        self.hosts_discovered: int = 0
        self.ports_found: int = 0
        self.anomalies_detected: int = 0
        self.vulns_found: int = 0
        self._lock = threading.Lock()

    def update(self, **kwargs) -> None:
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                'state': self.state,
                'current_phase': self.current_phase,
                'last_run_start': self.last_run_start,
                'last_run_end': self.last_run_end,
                'last_run_result': self.last_run_result,
                'total_runs': self.total_runs,
                'total_errors': self.total_errors,
                'hosts_discovered': self.hosts_discovered,
                'ports_found': self.ports_found,
                'anomalies_detected': self.anomalies_detected,
                'vulns_found': self.vulns_found,
            }


class HostVigilOrchestrator:
    """Main orchestrator coordinating all HostVigil modules."""

    def __init__(self, config_path: str = 'config.yaml'):
        self.config = Config(config_path)
        self.db_path = self.config.database['path']
        self.stealth_config = self.config.stealth
        self.scheduler_config = self.config.scheduler

        self.running = False
        self._shutdown_event = threading.Event()
        self._daemon_thread: Optional[threading.Thread] = None
        self.status = PipelineStatus()
        self._phase_last_run = {}  # Per-phase interval tracking

        # Setup logging (stealth: file-only)
        setup_logging()

        # Initialize database
        init_database(self.db_path)

        # Initialize modules
        self.discovery = StealthDiscovery(self.config.hostvigil, self.db_path)
        self.scanner = StealthScanner(self.config.hostvigil, self.db_path)
        self.ml_engine = AnomalyDetector(self.config.ml_engine, self.db_path)
        self.nuclei = NucleiRunner(self.config.nuclei, self.db_path)

        # Initialize deep-scan modules
        os_fp_config = {**self.stealth_config, **self.config.get('os_fingerprint', default={})}
        tls_config = {**self.stealth_config, **self.config.get('tls_inspection', default={})}
        enum_config = {**self.stealth_config, **self.config.get('service_enum', default={})}

        self.os_fingerprinter = OSFingerprinter(os_fp_config, self.db_path)
        self.tls_inspector = TLSInspector(tls_config, self.db_path)
        self.service_enum = ServiceEnumerator(enum_config, self.db_path)

        # ML enrichment engine (learns from feedback and history)
        self.ml_enrichment = MLEnrichmentEngine(self.config.ml_engine, self.db_path)

        logger.info("HostVigil Orchestrator initialized (db=%s)", str(Path(self.db_path).resolve()))

    # ------------------------------------------------------------------
    # Stealth Timing
    # ------------------------------------------------------------------

    def _stealth_delay(self, phase: str = 'inter-phase') -> None:
        """Apply randomized delay between pipeline phases for stealth."""
        if self._shutdown_event.is_set():
            return

        min_delay = self.stealth_config.get('min_delay', 10.0)
        max_delay = self.stealth_config.get('max_delay', 45.0)
        jitter = self.stealth_config.get('jitter_factor', 0.3)

        base_delay = random.uniform(min_delay, max_delay)
        jitter_amount = base_delay * random.uniform(-jitter, jitter)
        delay = max(1.0, base_delay + jitter_amount)

        logger.debug(f"Stealth delay ({phase}): {delay:.1f}s")
        self._shutdown_event.wait(timeout=delay)

        if self._shutdown_event.is_set():
            raise InterruptedError('Shutdown requested during stealth delay')

    # ------------------------------------------------------------------
    # Database Helpers
    # ------------------------------------------------------------------

    def _get_active_hosts(self) -> list[str]:
        """Retrieve active host IPs from the database."""
        try:
            conn = get_db_connection(self.db_path)
            try:
                rows = conn.execute(
                    "SELECT ip FROM hosts WHERE is_active = 1"
                ).fetchall()
                return [row[0] for row in rows]
            finally:
                conn.close()
        except Exception as e:
            logger.error(f"Failed to fetch active hosts: {e}")
            return []

    # ------------------------------------------------------------------
    # Individual Module Execution
    # ------------------------------------------------------------------

    def run_discovery(self) -> dict:
        """Execute host discovery phase."""
        self.status.update(current_phase='discovery')
        logger.info("Starting discovery phase")
        try:
            hosts = self.discovery.run_discovery()
            hosts_found = len(hosts) if isinstance(hosts, list) else 0
            self.status.update(hosts_discovered=self.status.hosts_discovered + hosts_found)
            logger.info(f"Discovery complete: {hosts_found} hosts found")
            return {'hosts_found': hosts_found, 'hosts': hosts}
        except Exception as e:
            logger.error(f"Discovery phase failed: {e}")
            self.status.update(total_errors=self.status.total_errors + 1)
            return {'error': str(e), 'hosts_found': 0}

    def run_scan(self) -> dict:
        """Execute port scanning phase on all active hosts."""
        self.status.update(current_phase='scanning')
        logger.info("Starting scan phase")
        try:
            hosts = self._get_active_hosts()
            if not hosts:
                logger.warning("No active hosts to scan")
                return {'ports_found': 0, 'reason': 'no active hosts'}

            results = self.scanner.scan_hosts(hosts, port_profile='standard')
            ports_found = len(results) if isinstance(results, list) else 0
            self.status.update(ports_found=self.status.ports_found + ports_found)
            logger.info(f"Scan complete: {ports_found} open ports found")
            return {'ports_found': ports_found, 'results': results}
        except Exception as e:
            logger.error(f"Scan phase failed: {e}")
            self.status.update(total_errors=self.status.total_errors + 1)
            return {'error': str(e), 'ports_found': 0}

    def run_analysis(self) -> dict:
        """Execute ML anomaly detection phase."""
        self.status.update(current_phase='ml_analysis')
        logger.info("Starting ML analysis phase")
        try:
            anomalies = self.ml_engine.detect_anomalies()
            count = len(anomalies) if isinstance(anomalies, list) else 0
            max_score = 0.0
            if anomalies:
                max_score = max((a.get('score', 0.0) for a in anomalies), default=0.0)
            self.status.update(anomalies_detected=self.status.anomalies_detected + count)
            logger.info(f"ML analysis complete: {count} anomalies detected")
            return {
                'anomalies_detected': count,
                'max_anomaly_score': max_score,
                'anomalies': anomalies,
            }
        except Exception as e:
            logger.error(f"ML analysis phase failed: {e}")
            self.status.update(total_errors=self.status.total_errors + 1)
            return {'error': str(e), 'anomalies_detected': 0}

    def run_nuclei(self) -> dict:
        """Execute Nuclei vulnerability scanning phase."""
        self.status.update(current_phase='nuclei')
        logger.info("Starting Nuclei scan phase")
        try:
            findings = self.nuclei.run_scan()
            vulns = len(findings) if isinstance(findings, list) else 0
            self.status.update(vulns_found=self.status.vulns_found + vulns)
            logger.info(f"Nuclei scan complete: {vulns} vulnerabilities found")
            return {'vulnerabilities_found': vulns, 'findings': findings}
        except Exception as e:
            logger.error(f"Nuclei scan phase failed: {e}")
            self.status.update(total_errors=self.status.total_errors + 1)
            return {'error': str(e), 'vulnerabilities_found': 0}

    def run_udp_scan(self) -> dict:
        """Execute UDP port scanning phase on all active hosts."""
        self.status.update(current_phase='udp_scanning')
        logger.info("Starting UDP scan phase")
        try:
            hosts = self._get_active_hosts()
            if not hosts:
                logger.warning("No active hosts for UDP scan")
                return {'ports_found': 0, 'reason': 'no active hosts'}

            udp_profile = self.config.scanner.get('udp_profile', 'standard')
            results = self.scanner.scan_udp(hosts, port_profile=udp_profile)
            ports_found = len(results) if isinstance(results, list) else 0
            logger.info(f"UDP scan complete: {ports_found} open/filtered ports found")
            return {'ports_found': ports_found, 'results': results}
        except Exception as e:
            logger.error(f"UDP scan phase failed: {e}")
            self.status.update(total_errors=self.status.total_errors + 1)
            return {'error': str(e), 'ports_found': 0}

    def run_os_fingerprint(self) -> dict:
        """Execute OS fingerprinting on all active hosts."""
        self.status.update(current_phase='os_fingerprint')
        logger.info("Starting OS fingerprinting phase")
        try:
            if not self.config.get('os_fingerprint', 'enabled', default=True):
                return {'skipped': True, 'reason': 'disabled in config'}

            results = self.os_fingerprinter.fingerprint_all()
            count = len(results) if isinstance(results, list) else 0
            logger.info(f"OS fingerprinting complete: {count} hosts fingerprinted")
            return {'hosts_fingerprinted': count, 'results': results}
        except Exception as e:
            logger.error(f"OS fingerprinting failed: {e}")
            self.status.update(total_errors=self.status.total_errors + 1)
            return {'error': str(e), 'hosts_fingerprinted': 0}

    def run_tls_inspection(self) -> dict:
        """Execute TLS inspection on hosts with TLS-enabled ports."""
        self.status.update(current_phase='tls_inspection')
        logger.info("Starting TLS inspection phase")
        try:
            if not self.config.get('tls_inspection', 'enabled', default=True):
                return {'skipped': True, 'reason': 'disabled in config'}

            results = self.tls_inspector.inspect_all()
            count = len(results) if isinstance(results, list) else 0
            weak_count = sum(1 for r in (results or []) if r.get('weaknesses'))
            logger.info(f"TLS inspection complete: {count} certs inspected, {weak_count} with weaknesses")
            return {'certs_inspected': count, 'weak_certs': weak_count, 'results': results}
        except Exception as e:
            logger.error(f"TLS inspection failed: {e}")
            self.status.update(total_errors=self.status.total_errors + 1)
            return {'error': str(e), 'certs_inspected': 0}

    def run_service_enum(self) -> dict:
        """Execute deep service enumeration on relevant ports."""
        self.status.update(current_phase='service_enum')
        logger.info("Starting service enumeration phase")
        try:
            if not self.config.get('service_enum', 'enabled', default=True):
                return {'skipped': True, 'reason': 'disabled in config'}

            results = self.service_enum.enumerate_all()
            count = len(results) if isinstance(results, list) else 0
            critical = sum(1 for r in (results or []) if r.get('risk_level') in ('critical', 'high'))
            logger.info(f"Service enumeration complete: {count} services checked, {critical} critical/high findings")
            return {'services_enumerated': count, 'critical_findings': critical, 'results': results}
        except Exception as e:
            logger.error(f"Service enumeration failed: {e}")
            self.status.update(total_errors=self.status.total_errors + 1)
            return {'error': str(e), 'services_enumerated': 0}

    # ------------------------------------------------------------------
    # Full Pipeline
    # ------------------------------------------------------------------

    def _should_run_nuclei(self, scan_results: dict, ml_results: dict, **extra_results) -> bool:
        """Determine if Nuclei should run based on scan/ML/enum results."""
        if not self.config.nuclei.get('auto_run', True):
            return False
        if scan_results.get('ports_found', 0) > 0:
            return True
        if ml_results.get('anomalies_detected', 0) > 0:
            return True
        high_score = ml_results.get('max_anomaly_score', 0.0)
        threshold = self.config.ml_engine.get('anomaly_threshold', 0.7)
        if high_score >= threshold:
            return True
        # Trigger on critical service enumeration findings
        enum_results = extra_results.get('enum_results', {})
        if enum_results.get('critical_findings', 0) > 0:
            return True
        # Trigger on TLS weaknesses
        tls_results = extra_results.get('tls_results', {})
        if tls_results.get('weak_certs', 0) > 0:
            return True
        return False

    def run_once(self) -> dict:
        """Execute the full pipeline once.

        Pipeline: Discovery -> Scan -> ML Analysis -> Nuclei (conditional)
        """
        self.status.update(
            state='running',
            last_run_start=now_iso(),
            last_run_end=None,
            last_run_result=None,
        )
        pipeline_results = {'start_time': now_iso(), 'phases': {}}

        logger.info("=" * 60)
        logger.info("Starting full pipeline execution")
        logger.info("=" * 60)

        try:
            # Phase 1: Discovery
            discovery_results = self.run_discovery()
            pipeline_results['phases']['discovery'] = {
                'hosts_found': discovery_results.get('hosts_found', 0)
            }
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay('post-discovery')

            # Phase 2: Port Scanning
            scan_results = self.run_scan()
            pipeline_results['phases']['scan'] = {
                'ports_found': scan_results.get('ports_found', 0)
            }
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay('post-scan')

            # Phase 2b: UDP Scanning
            if self.config.scanner.get('udp_scan_enabled', True):
                udp_results = self.run_udp_scan()
                pipeline_results['phases']['udp_scan'] = {
                    'ports_found': udp_results.get('ports_found', 0)
                }
                if self._shutdown_event.is_set():
                    raise InterruptedError("Shutdown requested")
                self._stealth_delay('post-udp-scan')

            # Phase 2c: OS Fingerprinting
            os_results = self.run_os_fingerprint()
            pipeline_results['phases']['os_fingerprint'] = {
                'hosts_fingerprinted': os_results.get('hosts_fingerprinted', 0)
            }
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay('post-os-fingerprint')

            # Phase 2d: TLS Inspection
            tls_results = self.run_tls_inspection()
            pipeline_results['phases']['tls_inspection'] = {
                'certs_inspected': tls_results.get('certs_inspected', 0),
                'weak_certs': tls_results.get('weak_certs', 0)
            }
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay('post-tls-inspection')

            # Phase 2e: Service Enumeration
            enum_results = self.run_service_enum()
            pipeline_results['phases']['service_enum'] = {
                'services_enumerated': enum_results.get('services_enumerated', 0),
                'critical_findings': enum_results.get('critical_findings', 0)
            }
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay('post-service-enum')

            # Phase 3: ML Analysis
            ml_results = self.run_analysis()
            pipeline_results['phases']['ml_analysis'] = {
                'anomalies_detected': ml_results.get('anomalies_detected', 0),
                'max_anomaly_score': ml_results.get('max_anomaly_score', 0.0),
            }
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")

            # Phase 4: Nuclei (conditional)
            if self._should_run_nuclei(scan_results, ml_results,
                                       enum_results=enum_results, tls_results=tls_results):
                self._stealth_delay('pre-nuclei')
                nuclei_results = self.run_nuclei()
                pipeline_results['phases']['nuclei'] = {
                    'vulnerabilities_found': nuclei_results.get('vulnerabilities_found', 0)
                }
            else:
                pipeline_results['phases']['nuclei'] = {'skipped': True, 'reason': 'no triggers'}
                logger.info("Nuclei scan skipped: no vulnerability indicators")

            pipeline_results['end_time'] = now_iso()
            pipeline_results['success'] = True
            self.status.update(
                state='idle',
                current_phase=None,
                last_run_end=now_iso(),
                last_run_result='success',
                total_runs=self.status.total_runs + 1,
            )
            logger.info("Pipeline execution complete")

        except InterruptedError:
            pipeline_results['end_time'] = now_iso()
            pipeline_results['success'] = False
            pipeline_results['interrupted'] = True
            self.status.update(
                state='stopped', current_phase=None,
                last_run_end=now_iso(), last_run_result='interrupted',
            )
            logger.warning("Pipeline interrupted by shutdown signal")

        except Exception as e:
            pipeline_results['end_time'] = now_iso()
            pipeline_results['success'] = False
            pipeline_results['error'] = str(e)
            self.status.update(
                state='idle', current_phase=None,
                last_run_end=now_iso(), last_run_result=f'error: {e}',
                total_errors=self.status.total_errors + 1,
            )
            logger.error(f"Pipeline failed: {e}")

        # Store for dashboard live display
        self._last_pipeline_result = pipeline_results
        self._store_scan_record(pipeline_results)
        return pipeline_results

    # ------------------------------------------------------------------
    # Continuous Daemon Mode
    # ------------------------------------------------------------------

    def run_continuous(self) -> None:
        """Run the pipeline continuously with stealth-randomized intervals.
        
        Excludes Nuclei from automatic runs (too resource-heavy for continuous mode).
        Nuclei must be triggered manually via dashboard button or CLI.
        Pipeline: Discovery -> Scan -> UDP Scan -> OS Fingerprint -> TLS -> Enum -> ML
        """
        self.running = True
        self.status.update(state='running')
        logger.info("HostVigil daemon started - continuous mode (Nuclei excluded)")

        discovery_interval = self.scheduler_config.get('discovery_interval_hours', 4) * 3600
        scan_interval = self.scheduler_config.get('scan_interval_hours', 2) * 3600
        base_interval = min(discovery_interval, scan_interval)

        run_count = 0

        while not self._shutdown_event.is_set():
            run_count += 1
            logger.info(f"Daemon cycle #{run_count} starting")
            self._run_daemon_cycle()

            if self._shutdown_event.is_set():
                break

            jitter = self.stealth_config.get('jitter_factor', 0.3)
            jitter_amount = base_interval * random.uniform(-jitter, jitter)
            wait_time = max(60.0, base_interval + jitter_amount)

            logger.info(f"Daemon cycle #{run_count} complete. Next in {wait_time / 60:.1f} min")
            self._shutdown_event.wait(timeout=wait_time)

        self.running = False
        self.status.update(state='stopped')
        logger.info("HostVigil daemon stopped")

    def _is_phase_due(self, phase_name: str) -> bool:
        """Check if a phase is due to run based on scheduler intervals."""
        import time as _time
        # Map phase names to scheduler interval config keys (all in hours)
        interval_map = {
            'discovery': self.scheduler_config.get('discovery_interval_hours', 4) * 3600,
            'scanning': self.scheduler_config.get('scan_interval_hours', 2) * 3600,
            'service_enum': self.scheduler_config.get('service_enum_interval_hours', 8) * 3600,
            'tls_inspection': self.scheduler_config.get('tls_inspection_interval_hours', 12) * 3600,
            'os_fingerprint': self.scheduler_config.get('os_fingerprint_interval_hours', 12) * 3600,
            'udp_scanning': self.scheduler_config.get('discovery_interval_hours', 4) * 3600,
            'ml_analysis': self.scheduler_config.get('scan_interval_hours', 2) * 3600,
        }
        interval = interval_map.get(phase_name, 0)
        if interval == 0:
            return True  # No interval configured, always run
        last_run = self._phase_last_run.get(phase_name, 0)
        return (_time.time() - last_run) >= interval

    def _mark_phase_run(self, phase_name: str) -> None:
        """Record that a phase just ran."""
        import time as _time
        self._phase_last_run[phase_name] = _time.time()

    def _run_daemon_cycle(self) -> dict:
        """Single daemon cycle: everything EXCEPT Nuclei.
        
        Nuclei is excluded from auto-runs to keep load low.
        Use the dashboard 'Nuclei Vuln Scan' button or `python run.py nuclei` to trigger it manually.
        """
        # Check scan window — skip cycle if outside allowed hours
        if self.stealth_config.get('scan_window_enabled', False):
            from datetime import datetime
            current_hour = datetime.now().hour
            window_start = self.stealth_config.get('scan_window_start', 8)
            window_end = self.stealth_config.get('scan_window_end', 18)
            if window_start <= window_end:
                in_window = window_start <= current_hour < window_end
            else:
                # Wraps midnight (e.g. start=22, end=6)
                in_window = current_hour >= window_start or current_hour < window_end
            if not in_window:
                logger.info("Outside scan window (hour=%d, window=%d-%d), skipping cycle",
                           current_hour, window_start, window_end)
                return {
                    'start_time': now_iso(),
                    'end_time': now_iso(),
                    'phases': {},
                    'mode': 'daemon',
                    'success': True,
                    'skipped': True,
                    'reason': 'outside_scan_window',
                }

        self.status.update(
            state='running',
            last_run_start=now_iso(),
            last_run_end=None,
            last_run_result=None,
        )
        pipeline_results = {'start_time': now_iso(), 'phases': {}, 'mode': 'daemon'}

        try:
            # Phase 1: Discovery
            if self._is_phase_due('discovery'):
                discovery_results = self.run_discovery()
                pipeline_results['phases']['discovery'] = {
                    'hosts_found': discovery_results.get('hosts_found', 0)
                }
                self._mark_phase_run('discovery')
            else:
                pipeline_results['phases']['discovery'] = {'skipped': True, 'reason': 'not due yet'}
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay('post-discovery')

            # Phase 2: TCP Port Scanning (immediate value — finds open services)
            if self._is_phase_due('scanning'):
                scan_results = self.run_scan()
                pipeline_results['phases']['scan'] = {
                    'ports_found': scan_results.get('ports_found', 0)
                }
                self._mark_phase_run('scanning')
            else:
                scan_results = {'ports_found': 0}
                pipeline_results['phases']['scan'] = {'skipped': True, 'reason': 'not due yet'}
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay('post-scan')

            # Phase 3: Service Enumeration (low-hanging fruit — no-auth services,
            # SMB null sessions, relay targets, exposed APIs)
            if self._is_phase_due('service_enum'):
                enum_results = self.run_service_enum()
                pipeline_results['phases']['service_enum'] = {
                    'services_enumerated': enum_results.get('services_enumerated', 0),
                    'critical_findings': enum_results.get('critical_findings', 0)
                }
                self._mark_phase_run('service_enum')
            else:
                pipeline_results['phases']['service_enum'] = {'skipped': True, 'reason': 'not due yet'}
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay('post-service-enum')

            # Phase 4: TLS Inspection (expired certs, weak ciphers — quick wins)
            if self._is_phase_due('tls_inspection'):
                tls_results = self.run_tls_inspection()
                pipeline_results['phases']['tls_inspection'] = {
                    'certs_inspected': tls_results.get('certs_inspected', 0),
                    'weak_certs': tls_results.get('weak_certs', 0)
                }
                self._mark_phase_run('tls_inspection')
            else:
                pipeline_results['phases']['tls_inspection'] = {'skipped': True, 'reason': 'not due yet'}
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay('post-tls-inspection')

            # Phase 5: OS Fingerprinting (enrichment, slower)
            if self._is_phase_due('os_fingerprint'):
                os_results = self.run_os_fingerprint()
                pipeline_results['phases']['os_fingerprint'] = {
                    'hosts_fingerprinted': os_results.get('hosts_fingerprinted', 0)
                }
                self._mark_phase_run('os_fingerprint')
            else:
                pipeline_results['phases']['os_fingerprint'] = {'skipped': True, 'reason': 'not due yet'}
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay('post-os-fingerprint')

            # Phase 6: UDP Scanning (slow, background enrichment)
            if self.config.scanner.get('udp_scan_enabled', True):
                if self._is_phase_due('udp_scanning'):
                    udp_results = self.run_udp_scan()
                    pipeline_results['phases']['udp_scan'] = {
                        'ports_found': udp_results.get('ports_found', 0)
                    }
                    self._mark_phase_run('udp_scanning')
                else:
                    pipeline_results['phases']['udp_scan'] = {'skipped': True, 'reason': 'not due yet'}
                if self._shutdown_event.is_set():
                    raise InterruptedError("Shutdown requested")
                self._stealth_delay('post-udp-scan')

            # Phase 7: ML Analysis
            if self._is_phase_due('ml_analysis'):
                ml_results = self.run_analysis()
                pipeline_results['phases']['ml_analysis'] = {
                    'anomalies_detected': ml_results.get('anomalies_detected', 0),
                    'max_anomaly_score': ml_results.get('max_anomaly_score', 0.0),
                }
                self._mark_phase_run('ml_analysis')
            else:
                pipeline_results['phases']['ml_analysis'] = {'skipped': True, 'reason': 'not due yet'}

            # Phase 7b: ML Enrichment (incremental learning)
            try:
                enrichment_result = self.ml_enrichment.incremental_update()
                pipeline_results['phases']['ml_enrichment'] = {
                    'temporal_updated': enrichment_result.get('temporal', {}).get('status') == 'updated',
                    'correlations_updated': enrichment_result.get('correlations', {}).get('status') == 'updated',
                    'drift_detected': enrichment_result.get('snapshot', {}).get('drift_detected', False),
                }
            except Exception as e:
                logger.error(f"ML enrichment update failed: {e}")
                pipeline_results['phases']['ml_enrichment'] = {'error': str(e)}

            # Nuclei is NOT auto-triggered in daemon mode
            pipeline_results['phases']['nuclei'] = {
                'skipped': True,
                'reason': 'daemon mode - use manual trigger'
            }

            pipeline_results['end_time'] = now_iso()
            pipeline_results['success'] = True
            self.status.update(
                state='running',  # Stay running in daemon mode
                current_phase=None,
                last_run_end=now_iso(),
                last_run_result='success',
                total_runs=self.status.total_runs + 1,
            )
            logger.info("Daemon cycle complete")

        except InterruptedError:
            pipeline_results['end_time'] = now_iso()
            pipeline_results['success'] = False
            pipeline_results['interrupted'] = True
            self.status.update(
                state='stopped', current_phase=None,
                last_run_end=now_iso(), last_run_result='interrupted',
            )

        except Exception as e:
            pipeline_results['end_time'] = now_iso()
            pipeline_results['success'] = False
            pipeline_results['error'] = str(e)
            self.status.update(
                current_phase=None,
                last_run_end=now_iso(), last_run_result=f'error: {e}',
                total_errors=self.status.total_errors + 1,
            )
            logger.error(f"Daemon cycle failed: {e}")

        # Store last pipeline result for dashboard consumption
        self._last_pipeline_result = pipeline_results
        self._store_scan_record(pipeline_results)
        return pipeline_results

    def _store_scan_record(self, results: dict):
        """Store a scan record in the scans table for dashboard history."""
        try:
            conn = get_db_connection(self.db_path)
            try:
                phases = results.get('phases', {})
                hosts_found = phases.get('discovery', {}).get('hosts_found', 0)
                ports_found = phases.get('scan', {}).get('ports_found', 0)
                conn.execute(
                    "INSERT INTO scans (scan_type, start_time, end_time, hosts_found, ports_found) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        results.get('mode', 'full'),
                        results.get('start_time', now_iso()),
                        results.get('end_time', now_iso()),
                        hosts_found,
                        ports_found,
                    )
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.error(f"Failed to store scan record: {e}")

    def start_daemon(self) -> None:
        """Start continuous mode in a background thread."""
        if self._daemon_thread and self._daemon_thread.is_alive():
            logger.warning("Daemon already running")
            return
        self._shutdown_event.clear()
        self._daemon_thread = threading.Thread(
            target=self.run_continuous, name='hostvigil-daemon', daemon=True,
        )
        self._daemon_thread.start()

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def run_dashboard(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        """Start the web dashboard."""
        import secrets as _secrets
        dashboard_config = self.config.dashboard
        bind_host = host or dashboard_config.get('host', '127.0.0.1')
        bind_port = port or dashboard_config.get('port', 5000)

        secret_key = dashboard_config.get('secret_key', 'hostvigil-default-key')
        if secret_key in ('change-this-in-production', 'hostvigil-default-key'):
            secret_key = _secrets.token_hex(32)
            logger.warning('Dashboard using auto-generated secret_key')

        app = create_app({
            'db_path': self.db_path,
            'secret_key': secret_key,
            'refresh_interval': dashboard_config.get('refresh_interval', 30),
            'orchestrator': self,
        })

        logger.info(f"Starting dashboard on {bind_host}:{bind_port}")
        print(f"[*] HostVigil Dashboard: http://{bind_host}:{bind_port}")
        print(f"[*] Press Ctrl+C to stop")
        app.run(host=bind_host, port=bind_port, debug=False, use_reloader=False)

    # ------------------------------------------------------------------
    # Status & Control
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Get current orchestrator and pipeline status."""
        db_stats = self._get_db_stats()
        return {
            'orchestrator': self.status.to_dict(),
            'database': db_stats,
            'config': {
                'stealth_min_delay': self.stealth_config.get('min_delay'),
                'stealth_max_delay': self.stealth_config.get('max_delay'),
                'scan_interval_hours': self.scheduler_config.get('scan_interval_hours'),
                'discovery_interval_hours': self.scheduler_config.get('discovery_interval_hours'),
                'nuclei_interval_hours': self.scheduler_config.get('nuclei_interval_hours'),
            },
        }

    def _get_db_stats(self) -> dict:
        """Query database for current statistics."""
        try:
            conn = get_db_connection(self.db_path)
            try:
                stats = {}
                stats['total_hosts'] = conn.execute(
                    "SELECT COUNT(*) FROM hosts"
                ).fetchone()[0]
                stats['active_hosts'] = conn.execute(
                    "SELECT COUNT(*) FROM hosts WHERE is_active = 1"
                ).fetchone()[0]
                stats['total_ports'] = conn.execute(
                    "SELECT COUNT(*) FROM ports WHERE is_active = 1"
                ).fetchone()[0]
                stats['total_vulnerabilities'] = conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities"
                ).fetchone()[0]
                stats['total_anomalies'] = conn.execute(
                    "SELECT COUNT(*) FROM anomalies"
                ).fetchone()[0]
                stats['total_scans'] = conn.execute(
                    "SELECT COUNT(*) FROM scans"
                ).fetchone()[0]
                return stats
            finally:
                conn.close()
        except Exception as e:
            logger.error(f"Failed to get DB stats: {e}")
            return {'error': str(e)}

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        """Graceful shutdown of all running operations."""
        logger.info("Shutdown requested")
        self.status.update(state='stopping')
        self._shutdown_event.set()
        self.running = False

        if self._daemon_thread and self._daemon_thread.is_alive():
            logger.info("Waiting for daemon thread to stop...")
            self._daemon_thread.join(timeout=30)
            if self._daemon_thread.is_alive():
                logger.warning("Daemon thread did not stop within timeout")

        self.status.update(state='stopped', current_phase=None)
        logger.info("HostVigil shutdown complete")

    def install_signal_handlers(self) -> None:
        """Install OS signal handlers for graceful shutdown."""
        def _handler(signum, frame):
            sig_name = signal.Signals(signum).name
            logger.info(f"Received signal {sig_name}")
            print(f"\n[!] Received {sig_name}, shutting down gracefully...")
            self.shutdown()
            # Clean PID file
            pid_file = Path('data/.hostvigil.pid')
            if pid_file.exists():
                pid_file.unlink(missing_ok=True)
            # Flush logs before force-exit
            import logging as _logging
            for h in _logging.getLogger('hostvigil').handlers:
                h.flush()
                h.close()
            # Force exit — Flask's socket accept() won't respond to sys.exit
            os._exit(0)

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, _handler)
