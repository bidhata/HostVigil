"""
Configuration loader for HostVigil.

Loads settings from config.yaml with sensible defaults as fallback.
"""

from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG: dict[str, Any] = {
    "hostvigil": {
        "stealth": {
            "min_delay": 10.0,
            "max_delay": 45.0,
            "max_threads": 3,
            "jitter_factor": 0.3,
            "packet_fragmentation": True,
            "randomize_scan_order": True,
            "ttl_manipulation": True,
            "decoy_ips": ["10.0.0.1", "10.0.0.254", "172.16.0.1", "192.168.1.1", "100.64.0.1", "198.18.0.1"],
        },
        "discovery": {
            "techniques": [
                "nmap_discover",
                "arp_sweep",
                "passive_sniff",
                "mdns_enum",
                "nbns_query",
                "dns_reverse_walk",
            ],
            "target_ranges": ["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "fe80::/10", "fc00::/7"],
            "passive_sniff_duration": 300,
            "arp_batch_size": 16,
            "arp_batch_delay": 5.0,
        },
        "scanner": {
            "ports": {
                "quick": [22, 80, 443, 445, 3389],
                "standard": [
                    22, 53, 80, 88, 135, 139, 389, 443, 445, 636,
                    1433, 3306, 3389, 5432, 5985, 5986, 8080, 8443, 9200,
                ],
                "full": [
                    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143,
                    389, 443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433,
                    1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5985,
                    5986, 6379, 8080, 8443, 8888, 9090, 9200, 9300, 11211, 27017,
                ],
            },
            "scan_type": "connect",
            "timeout": 1.5,
            "banner_grab": True,
            "service_detection": True,
        },
        "ml_engine": {
            "model_path": "data/models/",
            "training_interval_hours": 24,
            "anomaly_threshold": 0.7,
            "min_training_samples": 50,
            "features": [
                "port_count_per_host",
                "new_service_detection",
                "port_change_rate",
                "unusual_port_combinations",
                "banner_change_detection",
                "time_pattern_deviation",
            ],
        },
        "nuclei": {
            "binary_path": "nuclei",
            "templates_path": "",
            "severity_filter": ["critical", "high", "medium"],
            "rate_limit": 10,
            "bulk_size": 5,
            "concurrency": 2,
            "timeout": 15,
            "retries": 1,
            "auto_run": True,
            "run_interval_hours": 6,
        },
        "dashboard": {
            "host": "127.0.0.1",
            "port": 5000,
            "secret_key": "change-this-in-production",
            "refresh_interval": 30,
        },
        "scheduler": {
            "discovery_interval_hours": 4,
            "scan_interval_hours": 2,
            "ml_training_interval_hours": 24,
            "nuclei_interval_hours": 6,
        },
        "database": {
            "path": "data/hostvigil.db",
        },
    }
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


class Config:
    """HostVigil configuration manager."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        self._config_path = self._resolve_config_path(config_path)
        self._data = self._load_config()

    def _resolve_config_path(self, config_path: str | Path | None) -> Path:
        """Resolve the configuration file path."""
        if config_path:
            return Path(config_path)
        # Look relative to the project root (one level up from hostvigil package)
        project_root = Path(__file__).parent.parent
        return project_root / "config.yaml"

    def _load_config(self) -> dict[str, Any]:
        """Load configuration from YAML file, merged with defaults."""
        if self._config_path.exists():
            with open(self._config_path, "r", encoding="utf-8") as f:
                file_config = yaml.safe_load(f) or {}
            return _deep_merge(DEFAULT_CONFIG, file_config)
        return DEFAULT_CONFIG.copy()

    @property
    def hostvigil(self) -> dict[str, Any]:
        """Full 'hostvigil' config section containing all subsections.

        Some modules (e.g. StealthDiscovery, StealthScanner) expect the
        section that contains both 'stealth' and their own subsection, so
        they can resolve stealth-timing plus module-specific settings.
        """
        return self._data["hostvigil"]

    @property
    def stealth(self) -> dict[str, Any]:
        """Stealth configuration section."""
        return self._data["hostvigil"]["stealth"]

    @property
    def discovery(self) -> dict[str, Any]:
        """Discovery configuration section."""
        return self._data["hostvigil"]["discovery"]

    @property
    def scanner(self) -> dict[str, Any]:
        """Scanner configuration section."""
        return self._data["hostvigil"]["scanner"]

    @property
    def ml_engine(self) -> dict[str, Any]:
        """ML engine configuration section."""
        return self._data["hostvigil"]["ml_engine"]

    @property
    def nuclei(self) -> dict[str, Any]:
        """Nuclei configuration section."""
        return self._data["hostvigil"]["nuclei"]

    @property
    def dashboard(self) -> dict[str, Any]:
        """Dashboard configuration section."""
        return self._data["hostvigil"]["dashboard"]

    @property
    def scheduler(self) -> dict[str, Any]:
        """Scheduler configuration section."""
        return self._data["hostvigil"]["scheduler"]

    @property
    def database(self) -> dict[str, Any]:
        """Database configuration section."""
        return self._data["hostvigil"]["database"]

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a nested config value using dot-separated keys.

        Example: config.get('stealth', 'min_delay')
        """
        current = self._data["hostvigil"]
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def reload(self) -> None:
        """Reload configuration from disk."""
        self._data = self._load_config()

    def __repr__(self) -> str:
        return f"Config(path={self._config_path})"


# Module-level singleton for convenience
_config_instance: Config | None = None


def get_config(config_path: str | Path | None = None) -> Config:
    """Get or create the global Config singleton."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(config_path)
    return _config_instance
