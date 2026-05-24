"""
Configuration management for Vane Monitor
"""
import json
import os
from pathlib import Path
from typing import Any, Dict


class Config:
    """Configuration handler for Vane Monitor"""

    DEFAULT_CONFIG = {
        "client": {
            "server_url": "https://localhost:5000",
            "test_interval": 60,
            "client_id": "default_client",
            "verify_ssl": False,
            "tests": {
                "ping": {
                    "enabled": True,
                    "targets": ["8.8.8.8", "1.1.1.1", "google.com"],
                    "count": 4,
                    "timeout": 5,
                },
                "http": {
                    "enabled": True,
                    "targets": ["https://www.google.com", "https://www.cloudflare.com"],
                },
                "dns": {
                    "enabled": True,
                    "targets": ["google.com", "cloudflare.com"],
                    "dns_servers": ["8.8.8.8", "1.1.1.1"],
                },
                "traceroute": {
                    "enabled": False,
                    "targets": ["8.8.8.8"],
                },
            },
        },
        "server": {
            "host": "0.0.0.0",
            "port": 5000,
            "database": "vane_monitor.db",
            "max_data_age_days": 30,
            "dashboard": {
                "enabled": True,
                "refresh_interval": 30,
            },
            "ssl": {
                "enabled": False,
                "cert_file": "certs/server.crt",
                "key_file": "certs/server.key",
                "self_signed_generate": True,
            },
        },
        "logging": {
            "level": "INFO",
            "db": "vane_monitor_log.db",
        },
    }

    def __init__(self, config_file: str = None):
        self.config = self.DEFAULT_CONFIG.copy()

        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
        else:
            default_paths = [
                'config.json',
                'vane_monitor.json',
                Path.home() / '.vane_monitor' / 'config.json',
            ]

            for path in default_paths:
                if os.path.exists(path):
                    self.load_from_file(str(path))
                    break

    def load_from_file(self, filepath: str):
        try:
            with open(filepath, 'r') as f:
                user_config = json.load(f)
                self._merge_config(self.config, user_config)
        except Exception as exc:
            print(f"Warning: Could not load config from {filepath}: {exc}")

    def _merge_config(self, base: Dict, override: Dict):
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def save_to_file(self, filepath: str):
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(self.config, f, indent=4)

    def get(self, *keys, default=None) -> Any:
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, *keys, value):
        config = self.config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value

    @classmethod
    def create_default_config(cls, filepath: str = 'config.json'):
        config = cls()
        config.save_to_file(filepath)
        print(f"Default configuration created at: {filepath}")