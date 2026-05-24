"""
Shared constants used by both client and server.
Keep this file free of third-party imports so it can be
bundled into a PyInstaller executable without pulling in server deps.
"""

VERSION = "1.1.0"

API_AUTH_TOKEN = "/api/auth/token"
API_REGISTER = "/api/register"
API_SUBMIT = "/api/submit"
API_DESTINATIONS = "/api/destinations"
API_DNS_TEST_DOMAINS = "/api/dns-test-domains"
API_STATS = "/api/stats"
API_RESULTS = "/api/results"
API_CLIENTS = "/api/clients"
API_ALARMS = "/api/alarms"
API_ALARM_COUNTS = "/api/alarm-counts"
API_USERS = "/api/users"
API_SYSTEM_CONFIG = "/api/system-config"
API_LOGS = "/api/logs"

HEADER_API_KEY = "X-API-Key"
COOKIE_SESSION = "vane_session"
USER_AGENT = "VaneMonitor-Client/1.0"