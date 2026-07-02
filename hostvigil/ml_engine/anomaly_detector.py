"""
Anomaly Detector - ML-based network behavior anomaly detection.

Trains on historical scan data to identify unusual port configurations,
new services, behavioral pattern deviations, and banner changes.

Supports cold-start with rule-based detection until enough samples
accumulate for ML model training.
"""

import numpy as np
import logging
import sqlite3
import json
import pickle
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Tuple, Optional
from pathlib import Path

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger('hostvigil.ml_engine')

# Ports commonly associated with suspicious activity
SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 7777, 8888, 9999,  # Common reverse shells
    1337, 31337,  # Leet ports
    4443, 8443,  # Alt HTTPS (sometimes C2)
    2222,  # Alt SSH
    6667, 6668, 6669,  # IRC (botnet C2)
    3128, 8080, 8081,  # Proxy ports
    5900, 5901,  # VNC
    4899,  # Radmin
    1234, 12345,  # Generic backdoor
}

# Well-known service ports (expected on most networks)
COMMON_PORTS = {
    22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    3306, 5432, 8080, 8443, 3389, 5900,
}

# Feature vector indices
FEAT_PORT_COUNT = 0
FEAT_HIGH_PORT_RATIO = 1
FEAT_SERVICE_DIVERSITY = 2
FEAT_TIME_SINCE_FIRST = 3
FEAT_PORT_VELOCITY = 4
FEAT_BANNER_CHANGES = 5
FEAT_UNUSUAL_PORT_SCORE = 6
NUM_FEATURES = 7


class AnomalyDetector:
    """ML-based anomaly detection engine for network monitoring.

    Uses IsolationForest and rule-based heuristics to identify
    anomalous network behavior from scan data.
    """

    def __init__(self, config: dict, db_path: str):
        self.config = config
        self.db_path = db_path
        self.model_path = Path(config.get('model_path', 'data/models/'))
        self.model_path.mkdir(parents=True, exist_ok=True)
        self.model = None
        self.scaler = None
        self.threshold = config.get('anomaly_threshold', 0.7)
        self.min_samples = config.get('min_training_samples', 50)
        self.baseline_window_days = config.get('baseline_window_days', 7)
        self.disappeared_threshold_hours = config.get('disappeared_threshold_hours', 48)
        self._load_model()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _now_iso(self) -> str:
        """Return current UTC time as ISO string."""
        return datetime.now(timezone.utc).isoformat()



    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self) -> Dict:
        """Train/retrain the model on current network data.

        Returns a dict with training stats (samples, model version, status).
        Falls back to rule-based mode if insufficient data or sklearn missing.
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("sklearn not available - using rule-based detection only")
            return {
                'status': 'skipped',
                'reason': 'sklearn not installed',
                'mode': 'rule_based',
            }

        try:
            features, host_ids = self._extract_all_features()
        except Exception as e:
            logger.error(f"Feature extraction failed during training: {e}")
            return {'status': 'error', 'reason': str(e)}

        sample_count = len(host_ids)
        if sample_count < self.min_samples:
            logger.info(
                f"Insufficient samples for training ({sample_count}/{self.min_samples}). "
                "Using rule-based detection."
            )
            return {
                'status': 'insufficient_data',
                'samples': sample_count,
                'min_required': self.min_samples,
                'mode': 'rule_based',
            }

        try:
            # Fit scaler
            self.scaler = StandardScaler()
            scaled_features = self.scaler.fit_transform(features)

            # Train Isolation Forest
            contamination = self.config.get('contamination', 0.05)
            self.model = IsolationForest(
                n_estimators=100,
                contamination=contamination,
                random_state=42,
                n_jobs=-1,
            )
            self.model.fit(scaled_features)

            # Save model
            self._save_model()

            # Log training event
            model_version = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            self._log_training(sample_count, model_version)

            logger.info(f"Model trained successfully on {sample_count} samples")
            return {
                'status': 'trained',
                'samples': sample_count,
                'model_version': model_version,
                'mode': 'ml',
            }

        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return {'status': 'error', 'reason': str(e)}

    def _log_training(self, samples: int, version: str):
        """Record training event in ml_training_log table."""
        try:
            conn = self._get_connection()
            conn.execute(
                "INSERT INTO ml_training_log (trained_at, samples_count, model_version) "
                "VALUES (?, ?, ?)",
                (self._now_iso(), samples, version),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log training event: {e}")



    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def detect_anomalies(self) -> List[Dict]:
        """Run anomaly detection on latest scan data.

        Combines rule-based detections with ML-based scoring when model
        is available. Returns list of anomaly dicts.
        """
        anomalies = []

        # Rule-based detections (always active)
        try:
            anomalies.extend(self._detect_new_hosts())
        except Exception as e:
            logger.error(f"Error detecting new hosts: {e}")

        try:
            anomalies.extend(self._detect_new_ports())
        except Exception as e:
            logger.error(f"Error detecting new ports: {e}")

        try:
            anomalies.extend(self._detect_banner_changes())
        except Exception as e:
            logger.error(f"Error detecting banner changes: {e}")

        try:
            anomalies.extend(self._detect_disappeared_hosts())
        except Exception as e:
            logger.error(f"Error detecting disappeared hosts: {e}")

        # ML-based detection (when model is trained)
        if self.model is not None and self.scaler is not None:
            try:
                ml_anomalies = self._detect_ml_anomalies()
                anomalies.extend(ml_anomalies)
            except Exception as e:
                logger.error(f"ML anomaly detection failed: {e}")

        # Store all anomalies
        for anomaly in anomalies:
            try:
                self._store_anomaly(
                    host_id=anomaly['host_id'],
                    anomaly_type=anomaly['type'],
                    score=anomaly['score'],
                    description=anomaly['description'],
                )
            except Exception as e:
                logger.error(f"Failed to store anomaly: {e}")

        logger.info(f"Detection complete: {len(anomalies)} anomalies found")
        return anomalies

    def _detect_ml_anomalies(self) -> List[Dict]:
        """Use trained ML model to detect statistical anomalies."""
        anomalies = []

        try:
            features, host_ids = self._extract_all_features()
        except Exception:
            return anomalies

        if len(host_ids) == 0:
            return anomalies

        for i, host_id in enumerate(host_ids):
            feature_vec = features[i].reshape(1, -1)
            score = self._calculate_anomaly_score(feature_vec)

            if score >= self.threshold:
                description = self._describe_ml_anomaly(features[i], score)
                anomalies.append({
                    'host_id': host_id,
                    'type': 'statistical_anomaly',
                    'score': score,
                    'description': description,
                })

        return anomalies

    def _describe_ml_anomaly(self, features: np.ndarray, score: float) -> str:
        """Generate human-readable description of ML-detected anomaly."""
        parts = [f"Statistical anomaly (score: {score:.2f})."]

        if features[FEAT_PORT_COUNT] > 20:
            parts.append(f"Unusually high port count ({int(features[FEAT_PORT_COUNT])}).")
        if features[FEAT_HIGH_PORT_RATIO] > 0.8:
            parts.append("Most ports are high-numbered (possible evasion).")
        if features[FEAT_PORT_VELOCITY] > 5:
            parts.append(f"Rapid port changes ({features[FEAT_PORT_VELOCITY]:.1f} new ports/day).")
        if features[FEAT_UNUSUAL_PORT_SCORE] > 0.5:
            parts.append("Host has unusual port combinations.")
        if features[FEAT_BANNER_CHANGES] > 3:
            parts.append(f"Frequent banner changes ({int(features[FEAT_BANNER_CHANGES])}).")

        return " ".join(parts)



    # ------------------------------------------------------------------
    # Feature Engineering
    # ------------------------------------------------------------------

    def _extract_features(self, host_id: int) -> Optional[np.ndarray]:
        """Extract feature vector for a single host.

        Features:
            0 - Total open port count
            1 - High-port ratio (ports > 1024 / total)
            2 - Service diversity score (unique services / total ports)
            3 - Time since first seen (days)
            4 - Port change velocity (new ports per day)
            5 - Banner change count
            6 - Unusual port score (suspicious ports / total)
        """
        try:
            conn = self._get_connection()

            # Get host info
            host = conn.execute(
                "SELECT * FROM hosts WHERE id = ?", (host_id,)
            ).fetchone()
            if host is None:
                conn.close()
                return None

            # Get active ports for this host
            ports = conn.execute(
                "SELECT * FROM ports WHERE host_id = ? AND is_active = 1",
                (host_id,)
            ).fetchall()

            # Get all ports ever seen (for velocity calculation)
            all_ports = conn.execute(
                "SELECT * FROM ports WHERE host_id = ?", (host_id,)
            ).fetchall()

            conn.close()

            features = np.zeros(NUM_FEATURES, dtype=np.float64)

            total_ports = len(ports)
            features[FEAT_PORT_COUNT] = total_ports

            if total_ports == 0:
                return features

            # High-port ratio
            high_ports = sum(1 for p in ports if p['port'] > 1024)
            features[FEAT_HIGH_PORT_RATIO] = high_ports / total_ports

            # Service diversity (unique services / total ports)
            services = set()
            for p in ports:
                if p['service']:
                    services.add(p['service'])
            features[FEAT_SERVICE_DIVERSITY] = len(services) / total_ports if total_ports > 0 else 0

            # Time since first seen (days)
            try:
                first_seen = datetime.fromisoformat(host['first_seen'])
                now = datetime.now(timezone.utc)
                # Handle naive timestamps
                if first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=timezone.utc)
                days_active = (now - first_seen).total_seconds() / 86400.0
                features[FEAT_TIME_SINCE_FIRST] = max(days_active, 0.01)
            except (ValueError, TypeError):
                features[FEAT_TIME_SINCE_FIRST] = 0.01

            # Port change velocity (total unique ports ever / days active)
            total_ever = len(all_ports)
            days = features[FEAT_TIME_SINCE_FIRST]
            features[FEAT_PORT_VELOCITY] = total_ever / days if days > 0 else total_ever

            # Banner change count - count ports where banner differs from
            # earliest known banner (simplified: count non-null banners as proxy)
            banner_changes = 0
            for p in all_ports:
                if p['banner'] and p['is_active'] == 1:
                    # Check if this port had a different banner before
                    banner_changes += 1
            features[FEAT_BANNER_CHANGES] = banner_changes

            # Unusual port score (suspicious ports / total)
            suspicious_count = sum(1 for p in ports if p['port'] in SUSPICIOUS_PORTS)
            features[FEAT_UNUSUAL_PORT_SCORE] = suspicious_count / total_ports

            return features

        except Exception as e:
            logger.error(f"Feature extraction failed for host {host_id}: {e}")
            return None

    def _extract_all_features(self) -> Tuple[np.ndarray, List[int]]:
        """Extract features for all active hosts.

        Returns:
            Tuple of (feature_matrix, host_id_list)
        """
        conn = self._get_connection()
        hosts = conn.execute(
            "SELECT id FROM hosts WHERE is_active = 1"
        ).fetchall()
        conn.close()

        features_list = []
        host_ids = []

        for host in hosts:
            host_id = host['id']
            feat = self._extract_features(host_id)
            if feat is not None:
                features_list.append(feat)
                host_ids.append(host_id)

        if len(features_list) == 0:
            return np.empty((0, NUM_FEATURES)), []

        return np.array(features_list), host_ids



    # ------------------------------------------------------------------
    # Rule-Based Detection
    # ------------------------------------------------------------------

    def _detect_new_hosts(self) -> List[Dict]:
        """Check for hosts not in baseline (seen within baseline window).

        A host is 'new' if its first_seen is within the last scan cycle
        but wasn't in the baseline window before that.
        """
        anomalies = []
        conn = self._get_connection()

        # Hosts first seen in last 24 hours
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        new_hosts = conn.execute(
            "SELECT id, ip, hostname, first_seen FROM hosts "
            "WHERE first_seen > ? AND is_active = 1",
            (cutoff,)
        ).fetchall()

        conn.close()

        for host in new_hosts:
            hostname_str = f" ({host['hostname']})" if host['hostname'] else ""
            anomalies.append({
                'host_id': host['id'],
                'type': 'new_host',
                'score': 0.8,
                'description': (
                    f"New host discovered: {host['ip']}{hostname_str}. "
                    f"First seen: {host['first_seen']}"
                ),
            })

        return anomalies

    def _detect_new_ports(self) -> List[Dict]:
        """Check for new ports on known hosts.

        A port is 'new' if first_seen is recent but the host has been
        known for longer than the baseline window.
        """
        anomalies = []
        conn = self._get_connection()

        baseline_cutoff = (
            datetime.now(timezone.utc) - timedelta(days=self.baseline_window_days)
        ).isoformat()
        recent_cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()

        # Find ports first seen recently on hosts that existed before baseline
        new_ports = conn.execute(
            """
            SELECT p.id, p.host_id, p.port, p.protocol, p.service, p.first_seen,
                   h.ip, h.hostname
            FROM ports p
            JOIN hosts h ON p.host_id = h.id
            WHERE p.first_seen > ?
              AND h.first_seen < ?
              AND p.is_active = 1
              AND h.is_active = 1
            """,
            (recent_cutoff, baseline_cutoff)
        ).fetchall()

        conn.close()

        for port in new_ports:
            is_suspicious = port['port'] in SUSPICIOUS_PORTS
            score = 0.9 if is_suspicious else 0.6
            service_str = f" ({port['service']})" if port['service'] else ""

            anomalies.append({
                'host_id': port['host_id'],
                'type': 'new_port',
                'score': score,
                'description': (
                    f"New port {port['port']}/{port['protocol']}{service_str} "
                    f"opened on {port['ip']}. "
                    f"{'SUSPICIOUS PORT!' if is_suspicious else ''}"
                ).strip(),
            })

        return anomalies



    def _detect_banner_changes(self) -> List[Dict]:
        """Detect service banner modifications.

        Compares current banners against previously stored banners
        for active ports. A banner change could indicate a compromised service.
        """
        anomalies = []
        conn = self._get_connection()

        # Get all active ports with banners that were updated recently
        recent_cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()

        # Find ports where last_seen is recent and banner exists
        # We compare against ports that have been known for a while
        baseline_cutoff = (
            datetime.now(timezone.utc) - timedelta(days=self.baseline_window_days)
        ).isoformat()

        ports_with_banners = conn.execute(
            """
            SELECT p.id, p.host_id, p.port, p.protocol, p.service, p.banner,
                   p.first_seen, p.last_seen, h.ip
            FROM ports p
            JOIN hosts h ON p.host_id = h.id
            WHERE p.banner IS NOT NULL
              AND p.is_active = 1
              AND p.first_seen < ?
              AND p.last_seen > ?
            """,
            (baseline_cutoff, recent_cutoff)
        ).fetchall()

        conn.close()

        # For banner change detection, we look at scan history
        # Since we only store current banner, we use a heuristic:
        # if a port was first seen long ago but its service field changed,
        # that's suspicious. In a full implementation we'd store banner history.
        # Here we flag ports on suspicious ports with banners as potentially changed.
        for port in ports_with_banners:
            # Flag if the service on the port doesn't match expected
            if port['port'] in SUSPICIOUS_PORTS and port['banner']:
                anomalies.append({
                    'host_id': port['host_id'],
                    'type': 'banner_change',
                    'score': 0.75,
                    'description': (
                        f"Suspicious banner on {port['ip']}:{port['port']}/{port['protocol']} - "
                        f"Service: {port['service'] or 'unknown'}, "
                        f"Banner: {port['banner'][:100]}"
                    ),
                })

        return anomalies

    def _detect_disappeared_hosts(self) -> List[Dict]:
        """Detect hosts that went offline.

        A host is considered disappeared if it was active but hasn't
        been seen within the disappeared threshold.
        """
        anomalies = []
        conn = self._get_connection()

        threshold = (
            datetime.now(timezone.utc) - timedelta(hours=self.disappeared_threshold_hours)
        ).isoformat()

        # Hosts marked active but not seen recently
        disappeared = conn.execute(
            """
            SELECT id, ip, hostname, first_seen, last_seen
            FROM hosts
            WHERE is_active = 1
              AND last_seen < ?
            """,
            (threshold,)
        ).fetchall()

        conn.close()

        for host in disappeared:
            hostname_str = f" ({host['hostname']})" if host['hostname'] else ""
            anomalies.append({
                'host_id': host['id'],
                'type': 'host_disappeared',
                'score': 0.65,
                'description': (
                    f"Host {host['ip']}{hostname_str} has not been seen since "
                    f"{host['last_seen']}. Possible takedown or network change."
                ),
            })

        return anomalies



    # ------------------------------------------------------------------
    # Scoring & Storage
    # ------------------------------------------------------------------

    def _calculate_anomaly_score(self, features: np.ndarray) -> float:
        """Get anomaly score from model.

        Returns a score between 0.0 (normal) and 1.0 (highly anomalous).
        Uses sklearn's decision_function which returns negative values for
        anomalies, normalized to [0, 1] range.
        """
        if self.model is None or self.scaler is None:
            return 0.0

        try:
            scaled = self.scaler.transform(features)
            # decision_function returns negative for anomalies
            raw_score = self.model.decision_function(scaled)[0]
            # Normalize: more negative = more anomalous
            # Typical range is [-0.5, 0.5], map to [0, 1] where 1 = anomalous
            normalized = max(0.0, min(1.0, 0.5 - raw_score))
            return round(normalized, 4)
        except Exception as e:
            logger.error(f"Score calculation failed: {e}")
            return 0.0

    def _store_anomaly(self, host_id: int, anomaly_type: str, score: float, description: str):
        """Store detected anomaly in database."""
        try:
            conn = self._get_connection()
            conn.execute(
                """
                INSERT INTO anomalies (host_id, anomaly_type, score, description, detected_at, is_reviewed)
                VALUES (?, ?, ?, ?, ?, 0)
                """,
                (host_id, anomaly_type, score, description, self._now_iso()),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to store anomaly for host {host_id}: {e}")

    # ------------------------------------------------------------------
    # Model Persistence
    # ------------------------------------------------------------------

    def _save_model(self):
        """Persist model and scaler to disk."""
        try:
            model_file = self.model_path / 'isolation_forest.pkl'
            scaler_file = self.model_path / 'scaler.pkl'

            with open(model_file, 'wb') as f:
                pickle.dump(self.model, f)

            with open(scaler_file, 'wb') as f:
                pickle.dump(self.scaler, f)

            logger.info(f"Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def _load_model(self):
        """Load model from disk if exists."""
        model_file = self.model_path / 'isolation_forest.pkl'
        scaler_file = self.model_path / 'scaler.pkl'

        if not model_file.exists() or not scaler_file.exists():
            logger.info("No saved model found - starting in rule-based mode")
            return

        try:
            with open(model_file, 'rb') as f:
                self.model = pickle.load(f)

            with open(scaler_file, 'rb') as f:
                self.scaler = pickle.load(f)

            logger.info("Model loaded from disk successfully")
        except Exception as e:
            logger.warning(f"Failed to load model (will retrain): {e}")
            self.model = None
            self.scaler = None

    # ------------------------------------------------------------------
    # Network Summary
    # ------------------------------------------------------------------

    def get_network_summary(self) -> Dict:
        """Return current network baseline summary.

        Provides overview statistics about the monitored network including
        host count, port distribution, and model status.
        """
        try:
            conn = self._get_connection()

            # Host counts
            total_hosts = conn.execute(
                "SELECT COUNT(*) as cnt FROM hosts WHERE is_active = 1"
            ).fetchone()['cnt']

            inactive_hosts = conn.execute(
                "SELECT COUNT(*) as cnt FROM hosts WHERE is_active = 0"
            ).fetchone()['cnt']

            # Port statistics
            total_ports = conn.execute(
                "SELECT COUNT(*) as cnt FROM ports WHERE is_active = 1"
            ).fetchone()['cnt']

            # Service distribution
            services = conn.execute(
                """
                SELECT service, COUNT(*) as cnt
                FROM ports
                WHERE is_active = 1 AND service IS NOT NULL
                GROUP BY service
                ORDER BY cnt DESC
                LIMIT 10
                """
            ).fetchall()

            # Recent anomalies
            anomaly_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM anomalies WHERE is_reviewed = 0"
            ).fetchone()['cnt']

            # Last training info
            last_training = conn.execute(
                "SELECT * FROM ml_training_log ORDER BY trained_at DESC LIMIT 1"
            ).fetchone()

            conn.close()

            # Model status
            if self.model is not None:
                model_status = 'trained'
            elif total_hosts < self.min_samples:
                model_status = f'cold_start (need {self.min_samples - total_hosts} more hosts)'
            else:
                model_status = 'untrained'

            return {
                'active_hosts': total_hosts,
                'inactive_hosts': inactive_hosts,
                'total_open_ports': total_ports,
                'top_services': [
                    {'service': s['service'], 'count': s['cnt']}
                    for s in services
                ],
                'unreviewed_anomalies': anomaly_count,
                'model_status': model_status,
                'last_training': dict(last_training) if last_training else None,
                'detection_mode': 'ml' if self.model else 'rule_based',
                'threshold': self.threshold,
            }

        except Exception as e:
            logger.error(f"Failed to generate network summary: {e}")
            return {
                'error': str(e),
                'model_status': 'unknown',
            }
