"""
Shared package for Vane Monitor.
Contains code used by both client and server:
  - config       - configuration management
  - log_handler  - SQLite-backed logging
  - constants    - API paths, version string
  - monitor/     - network test primitives (ping, dns, http, traceroute ...)

Import convention:
    from shared.config import Config
    from shared.monitor.network_tests import NetworkMonitor
"""