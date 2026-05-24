#!/usr/bin/env python3
"""
Vane Monitor — Client entry point.

Usage:
    python -m client.main                     # from repo root
    python main.py                            # from client/ directory
    python main.py --config client_config.json

When built as a single .exe the client creates its data files
(config, logs, ASN cache) next to the executable on first run.
"""
import sys
import os
from pathlib import Path


def get_app_dir() -> Path:
    """Return the directory where runtime data files should live.

    - Frozen .exe (PyInstaller --onefile): directory containing the .exe
    - Normal Python execution: the client/ package directory
    """
    if getattr(sys, 'frozen', False):
        # PyInstaller --onefile extracts to a temp dir, but the .exe
        # itself lives at sys.executable's parent.
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


# ── Make sure the repo root is importable ────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
# ─────────────────────────────────────────────────────────────────

# Set the working directory to app_dir so that any library that
# writes files relative to CWD (ASN cache, log DB, …) puts them
# next to the executable.
APP_DIR = get_app_dir()
os.makedirs(APP_DIR, exist_ok=True)
os.chdir(APP_DIR)

import argparse
import logging
import json
import getpass

from shared.log_handler import SQLiteLogHandler
from shared.constants import VERSION

# ── Logging ──────────────────────────────────────────────────────
_log_db = str(APP_DIR / "vane_monitor_log.db")
_db_handler = SQLiteLogHandler(_log_db)
_db_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
))
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[_db_handler, logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def get_default_config_path() -> Path:
    """Return the canonical client config path inside app_dir."""
    return APP_DIR / "client_config.json"


def run_client(config_file=None):
    """Start the client after optional interactive setup."""
    logger.info("Starting Vane Monitor CLIENT v%s", VERSION)

    resolved = (
        str(Path(config_file).resolve()) if config_file
        else str(get_default_config_path())
    )

    needs_setup = False

    if os.path.exists(resolved) and resolved.endswith("client_config.json"):
        try:
            with open(resolved, "r") as f:
                cfg = json.load(f)
            name = cfg.get("client_name", "")
            url  = cfg.get("server_url", "")
            defaults_n = {"my_client", "unknown_client", "default_client", ""}
            defaults_u = {"http://localhost:5000", ""}
            if name in defaults_n or url in defaults_u:
                needs_setup = True
        except Exception as exc:
            logger.warning("Could not read %s: %s", resolved, exc)
            needs_setup = True
    elif not config_file:
        needs_setup = True

    if needs_setup:
        _interactive_setup(resolved)

    try:
        from client.client import NetworkClient  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        from client import NetworkClient
    client = NetworkClient(resolved)
    client.start()


def _interactive_setup(config_path: str):
    print("\n" + "=" * 60)
    print("  CLIENT CONFIGURATION SETUP")
    print("=" * 60 + "\n")

    while True:
        client_name = input("Client name (e.g. office_london): ").strip()
        if client_name and client_name not in {"my_client", "unknown_client", "default_client"}:
            break
        print("❌  Please enter a unique client name.\n")

    while True:
        server_url = input("Server URL (e.g. https://192.168.1.100:5000): ").strip()
        if server_url and not server_url.startswith("http"):
            server_url = "https://" + server_url
        if server_url and server_url not in {"http://localhost:5000", "https://localhost:5000", ""}:
            break
        print("❌  Please enter a valid server URL (not localhost).\n")

    verify_ssl = True
    if server_url.startswith("https://"):
        ans = input("Verify SSL certificate? (yes/no) [no]: ").strip().lower()
        verify_ssl = ans in ("yes", "y", "true")

    raw = input("Test interval in seconds [60]: ").strip()
    test_interval = int(raw) if raw.isdigit() else 60

    print("\nClient API authentication is required.")
    print("Enter an existing API key, or leave blank to authenticate later.\n")
    api_key = input("API key (optional): ").strip()

    data = {
        "client_name": client_name,
        "server_url":  server_url,
        "test_interval": test_interval,
        "verify_ssl": verify_ssl,
        "api_key": api_key,
    }

    try:
        os.makedirs(os.path.dirname(config_path) or ".", exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(data, f, indent=4)
        print(f"\n✅  Saved to {config_path}")
    except Exception as exc:
        logger.error("Failed to save config: %s", exc)
        print(f"\n❌  {exc}")

    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Vane Monitor Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", type=str, help="Path to configuration file")
    parser.add_argument("--version", action="version", version=f"Vane Monitor Client {VERSION}")
    args = parser.parse_args()

    try:
        run_client(args.config)
    except KeyboardInterrupt:
        logger.info("Shutting down client …")
        sys.exit(0)
    except Exception as exc:
        logger.error("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
