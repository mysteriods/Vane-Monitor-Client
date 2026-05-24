"""
Network monitoring client
Runs scheduled tests and sends results to server
"""
import time
import logging
import json
import os
import sys
from pathlib import Path
import ssl
import getpass
import urllib.request
import urllib.error
import platform
import subprocess
import socket
import re
import shutil
import ctypes
from datetime import datetime
from typing import Any, Dict, List, Optional
from shared.config import Config
from shared.monitor.network_tests import NetworkMonitor

try:
    from client.offline_queue import PendingSubmissionStore  # type: ignore[import-not-found]
except ModuleNotFoundError:
    from offline_queue import PendingSubmissionStore

logger = logging.getLogger(__name__)


class NetworkClient:
    """Client that performs network tests and reports to server"""
    
    def __init__(self, config_file: Optional[str] = None, server_url: Optional[str] = None):
        """Initialize the network client"""

        # Determine the data directory: next to .exe (frozen) or client/ (dev)
        if getattr(sys, 'frozen', False):
            app_dir = Path(sys.executable).resolve().parent
        else:
            app_dir = Path(__file__).resolve().parent
        self.app_dir = app_dir
        default_client_config = app_dir / 'client_config.json'

        # Prefer project-root client_config.json unless an explicit config file was provided.
        if config_file is None:
            if default_client_config.exists():
                config_file = str(default_client_config)
                logger.info("Using client_config.json for configuration")

        self.config_file = config_file
        self.is_client_config = bool(config_file and config_file.endswith('client_config.json'))
        
        # Load configuration
        if config_file and config_file.endswith('client_config.json'):
            # Simplified config file
            try:
                with open(config_file, 'r') as f:
                    client_config = json.load(f)
                self.client_name = client_config.get('client_name', 'unknown_client')
                self.server_url = server_url or client_config.get('server_url', 'http://labtop.amjad.sbs:5000')
                self.test_interval = client_config.get('test_interval', 60)
                self.verify_ssl = client_config.get('verify_ssl', True)
                self.client_username = client_config.get('client_username', '')
                self.client_password = client_config.get('client_password', '')
                self.api_key = client_config.get('api_key', '')
                self.enable_l4s_testing = client_config.get('enable_l4s_testing', True)
                self.l4s_target = client_config.get('l4s_target', '1.1.1.1')
                self.l4s_interval = int(client_config.get('l4s_interval', 600))
            except Exception as e:
                logger.error(f"Error loading client_config.json: {e}")
                raise
        else:
            # Legacy config.json format
            self.config = Config(config_file)
            if server_url:
                self.server_url = server_url
            else:
                self.server_url = self.config.get('client', 'server_url')
            
            # Support both 'client_name' and 'client_id' for backward compatibility
            self.client_name = self.config.get('client', 'client_name',
                                              default=self.config.get('client', 'client_id', default='default_client'))
            self.test_interval = self.config.get('client', 'test_interval')
            self.verify_ssl = self.config.get('client', 'verify_ssl', default=True)
            self.client_username = self.config.get('client', 'username', default='')
            self.client_password = self.config.get('client', 'password', default='')
            self.api_key = self.config.get('client', 'api_key', default='')
            self.enable_l4s_testing = self.config.get('client', 'enable_l4s_testing', default=True)
            self.l4s_target = self.config.get('client', 'l4s_target', default='1.1.1.1')
            self.l4s_interval = int(self.config.get('client', 'l4s_interval', default=600))
        
        self.monitor = NetworkMonitor()
        self.running = False
        self.registered = False
        self.ssl_context = self._build_ssl_context()
        self._host_info_permission_denied = False
        self._last_l4s_run: float = 0.0  # epoch seconds; 0 = never run
        self._active_run_serial: Optional[int] = None
        self._active_run_started_at: Optional[str] = None
        self.pending_submission_store = PendingSubmissionStore(app_dir / 'pending_results.db')
        
        logger.info(f"Client initialized: {self.client_name}")
        logger.info(f"Server URL: {self.server_url}")
        logger.info(f"Test interval: {self.test_interval} seconds")

    def _save_runtime_auth_state(self):
        """Persist the current API key and avoid storing plaintext credentials."""
        if not self.config_file or not os.path.exists(self.config_file):
            return

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)

            if self.is_client_config:
                config_data['client_name'] = self.client_name
                config_data['api_key'] = self.api_key
                config_data.pop('client_username', None)
                config_data.pop('client_password', None)
            else:
                client_section = config_data.setdefault('client', {})
                client_section['client_name'] = self.client_name
                client_section['api_key'] = self.api_key
                client_section.pop('username', None)
                client_section.pop('password', None)

            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4)
        except Exception as e:
            logger.warning(f"Could not persist client API key state to {self.config_file}: {e}")

    def _clear_saved_api_key(self):
        """Remove the stored API key from disk after authentication failure."""
        self.api_key = ''
        self._save_runtime_auth_state()

    def _invalidate_api_key(self):
        """Clear a rejected API key from memory and disk."""
        logger.warning("Stored API key was rejected by the server; clearing it and re-authenticating")
        self._clear_saved_api_key()

    def _perform_authenticated_request(self, request_factory, timeout: int = 10):
        """Execute an authenticated request, reauthenticating once if the API key is rejected."""
        for attempt in range(2):
            try:
                request = request_factory()
                with self._open_url(request, timeout=timeout) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as e:
                if e.code != 401:
                    raise

                if attempt == 1:
                    raise

                self._invalidate_api_key()
                if not self.ensure_authenticated():
                    raise

        raise RuntimeError("Authenticated request failed unexpectedly")

    @staticmethod
    def _build_run_serial(loop_started_at: datetime) -> int:
        """Build a monotonic, time-derived serial for a test loop."""
        return int(loop_started_at.timestamp() * 1000)

    def _prepare_submission_payload(self, results: list, host_network_info: Optional[dict] = None,
                                    run_serial: Optional[int] = None,
                                    run_started_at: Optional[str] = None) -> Dict[str, Any]:
        payload_results = []
        for raw_result in results:
            item = dict(raw_result)

            if run_serial is not None:
                item['run_serial'] = run_serial
            if run_started_at:
                item['run_started_at'] = run_started_at
            if host_network_info and 'host_network_info' not in item:
                item['host_network_info'] = host_network_info

            rd = item.get('result_data')
            if isinstance(rd, dict):
                rd = dict(rd)
                if host_network_info and 'host_network_info' not in rd:
                    rd['host_network_info'] = host_network_info
                if run_serial is not None:
                    rd['run_serial'] = run_serial
                if run_started_at:
                    rd['run_started_at'] = run_started_at
                item['result_data'] = rd
            elif rd is None and (host_network_info or run_serial is not None or run_started_at):
                rd = {}
                if host_network_info:
                    rd['host_network_info'] = host_network_info
                if run_serial is not None:
                    rd['run_serial'] = run_serial
                if run_started_at:
                    rd['run_started_at'] = run_started_at
                item['result_data'] = rd

            payload_results.append(item)

        return {
            'client_id': self.client_name,
            'results': payload_results
        }

    def _submit_payload(self, payload: Dict[str, Any], timeout: int = 10) -> bool:
        json_data = json.dumps(payload).encode('utf-8')

        status, _ = self._perform_authenticated_request(
            lambda: urllib.request.Request(
                f"{self.server_url}/api/submit",
                data=json_data,
                headers={
                    'Content-Type': 'application/json',
                    **self._get_auth_headers()
                },
                method='POST'
            ),
            timeout=timeout
        )
        if status == 200:
            logger.info(
                "Successfully sent %s test result(s) to server",
                len(payload.get('results', []))
            )
            return True

        logger.error(f"Server responded with status: {status}")
        return False

    def _queue_submission(self, payload: Dict[str, Any]) -> None:
        first_result = payload.get('results', [{}])[0] if payload.get('results') else {}
        run_serial = first_result.get('run_serial')
        self.pending_submission_store.enqueue(
            client_id=payload.get('client_id', self.client_name),
            run_serial=run_serial,
            payload=payload,
        )

    def _flush_pending_submissions(self) -> bool:
        if not self.pending_submission_store.has_pending():
            return True

        pending_count = self.pending_submission_store.count_pending()
        logger.info("Attempting to replay %s queued submission(s)", pending_count)

        while True:
            pending_items = self.pending_submission_store.list_pending(limit=1)
            if not pending_items:
                return True

            item = pending_items[0]
            try:
                if self._submit_payload(item['payload']):
                    self.pending_submission_store.delete(item['id'])
                    logger.info(
                        "Replayed queued submission %s (run_serial=%s)",
                        item['id'],
                        item.get('run_serial')
                    )
                    continue

                error_text = 'Server rejected queued submission'
            except urllib.error.HTTPError as e:
                error_text = f"HTTP error while replaying queued submission: {e}"
                logger.warning(error_text)
            except urllib.error.URLError as e:
                error_text = f"Server still unavailable while replaying queued submission: {e}"
                logger.warning(error_text)
            except Exception as e:
                error_text = f"Unexpected error while replaying queued submission: {e}"
                logger.warning(error_text)

            self.pending_submission_store.mark_attempt(item['id'], error_text)
            return False

    def _build_ssl_context(self):
        """Build urllib SSL context based on client verification settings."""
        if isinstance(self.server_url, str) and self.server_url.startswith('https://') and not self.verify_ssl:
            logger.warning("SSL certificate verification is disabled for this client")
            return ssl._create_unverified_context()
        return None

    def _open_url(self, request: urllib.request.Request, timeout: int = 10):
        """Open a URL using the configured SSL context when needed."""
        if self.ssl_context is not None:
            return urllib.request.urlopen(request, timeout=timeout, context=self.ssl_context)
        return urllib.request.urlopen(request, timeout=timeout)

    def _run_command(self, args, timeout: int = 5) -> str:
        """Run a command and return stdout as text (best effort)."""
        out = subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', errors='ignore')

    def _looks_like_permission_error(self, error_text: str) -> bool:
        if not error_text:
            return False
        text = error_text.lower()
        return (
            'permission denied' in text or
            'operation not permitted' in text or
            'access is denied' in text or
            'requires elevation' in text
        )

    def _collect_wan_ip(self) -> Optional[str]:
        """Try to get WAN IP. Returns None if unavailable/restricted."""
        providers = [
            'https://api.ipify.org?format=json',
            'https://ifconfig.me/ip'
        ]
        for url in providers:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'VaneMonitor-Client/1.0'})
                with self._open_url(req, timeout=3) as response:
                    payload = response.read().decode('utf-8', errors='ignore').strip()
                    if payload.startswith('{'):
                        parsed = json.loads(payload)
                        ip = parsed.get('ip')
                        if ip:
                            return ip
                    elif payload:
                        return payload
            except Exception:
                continue
        return None

    def _collect_uptime_seconds(self) -> Optional[int]:
        """Collect host uptime in seconds (best effort)."""
        try:
            system = platform.system().lower()
            if system == 'windows':
                return int(ctypes.windll.kernel32.GetTickCount64() / 1000)

            if os.path.exists('/proc/uptime'):
                with open('/proc/uptime', 'r', encoding='utf-8', errors='ignore') as f:
                    first = f.read().strip().split()[0]
                    return int(float(first))
        except Exception:
            pass
        return None

    def _collect_memory_info(self) -> dict:
        """Collect memory/page-file information (best effort)."""
        info = {
            'used_bytes': None,
            'available_bytes': None,
            'total_bytes': None,
            'page_file_used_bytes': None,
            'page_file_available_bytes': None,
            'page_file_total_bytes': None
        }

        system = platform.system().lower()
        if system == 'windows':
            try:
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ('dwLength', ctypes.c_ulong),
                        ('dwMemoryLoad', ctypes.c_ulong),
                        ('ullTotalPhys', ctypes.c_ulonglong),
                        ('ullAvailPhys', ctypes.c_ulonglong),
                        ('ullTotalPageFile', ctypes.c_ulonglong),
                        ('ullAvailPageFile', ctypes.c_ulonglong),
                        ('ullTotalVirtual', ctypes.c_ulonglong),
                        ('ullAvailVirtual', ctypes.c_ulonglong),
                        ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
                    ]

                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                ok = ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                if ok:
                    info['total_bytes'] = int(stat.ullTotalPhys)
                    info['available_bytes'] = int(stat.ullAvailPhys)
                    info['used_bytes'] = int(stat.ullTotalPhys - stat.ullAvailPhys)
                    info['page_file_total_bytes'] = int(stat.ullTotalPageFile)
                    info['page_file_available_bytes'] = int(stat.ullAvailPageFile)
                    info['page_file_used_bytes'] = int(stat.ullTotalPageFile - stat.ullAvailPageFile)
                    return info
            except Exception:
                return info

        # Linux fallback using /proc/meminfo
        try:
            mem = {}
            if os.path.exists('/proc/meminfo'):
                with open('/proc/meminfo', 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if ':' not in line:
                            continue
                        k, v = line.split(':', 1)
                        parts = v.strip().split()
                        if parts and parts[0].isdigit():
                            mem[k.strip()] = int(parts[0]) * 1024  # kB -> bytes

                total = mem.get('MemTotal')
                available = mem.get('MemAvailable')
                if total is not None and available is not None:
                    info['total_bytes'] = total
                    info['available_bytes'] = available
                    info['used_bytes'] = total - available

                swap_total = mem.get('SwapTotal')
                swap_free = mem.get('SwapFree')
                if swap_total is not None and swap_free is not None:
                    info['page_file_total_bytes'] = swap_total
                    info['page_file_available_bytes'] = swap_free
                    info['page_file_used_bytes'] = swap_total - swap_free
        except Exception:
            pass

        return info

    def _collect_main_drive_info(self) -> dict:
        """Collect main/system drive usage (best effort)."""
        info = {
            'mount': None,
            'used_bytes': None,
            'total_bytes': None,
            'available_bytes': None
        }
        try:
            system = platform.system().lower()
            if system == 'windows':
                mount = os.environ.get('SystemDrive', 'C:') + '\\'
            else:
                mount = '/'

            total, used, free = shutil.disk_usage(mount)
            info['mount'] = mount
            info['used_bytes'] = int(used)
            info['total_bytes'] = int(total)
            info['available_bytes'] = int(free)
        except Exception:
            pass
        return info

    def _filter_addressed_interfaces(self, interfaces: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Keep only interfaces that have at least one IPv4 or IPv6 address."""
        filtered_interfaces = []
        for info in interfaces.values():
            ipv4_addresses = info.get('ipv4') or []
            ipv6_addresses = info.get('ipv6') or []
            if ipv4_addresses or ipv6_addresses:
                filtered_interfaces.append(info)
        return filtered_interfaces

    def _collect_windows_host_info(self) -> dict:
        interfaces = {}
        routes = []

        try:
            text = self._run_command(['netsh', 'interface', 'show', 'interface'])
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith('Admin') or line.startswith('-'):
                    continue
                parts = re.split(r'\s{2,}', line)
                if len(parts) >= 4:
                    iface_name = parts[3].strip()
                    iface_type = parts[2].strip().lower()
                    interfaces.setdefault(iface_name, {
                        'name': iface_name,
                        'type': 'wireless' if 'wireless' in iface_type else 'wired',
                        'speed_mbps': None,
                        'signal_strength': None,
                        'ipv4': [],
                        'ipv6': []
                    })
        except Exception as e:
            if self._looks_like_permission_error(str(e)):
                raise PermissionError(str(e))

        # IP addresses
        try:
            text = self._run_command(['ipconfig'])
            current = None
            for raw in text.splitlines():
                line = raw.rstrip()
                if line and not line.startswith(' ') and ':' in line:
                    header = line.strip().rstrip(':')
                    if 'adapter' in header.lower():
                        current = header.split('adapter', 1)[-1].strip()
                        interfaces.setdefault(current, {
                            'name': current,
                            'type': 'unknown',
                            'speed_mbps': None,
                            'signal_strength': None,
                            'ipv4': [],
                            'ipv6': []
                        })
                    continue

                if not current:
                    continue
                l = line.strip()
                if l.lower().startswith('ipv4') and ':' in l:
                    ip = l.split(':', 1)[1].strip().split('(')[0].strip()
                    if ip and ip not in interfaces[current]['ipv4']:
                        interfaces[current]['ipv4'].append(ip)
                elif l.lower().startswith('ipv6') and ':' in l:
                    ip = l.split(':', 1)[1].strip()
                    if ip and ip not in interfaces[current]['ipv6']:
                        interfaces[current]['ipv6'].append(ip)
        except Exception:
            pass

        # Link speed and connection type details via PowerShell (best effort)
        try:
            ps = "Get-NetAdapter | Select-Object Name, InterfaceDescription, LinkSpeed, NdisPhysicalMedium | ConvertTo-Json -Compress"
            text = self._run_command(['powershell', '-NoProfile', '-Command', ps], timeout=8)
            adapters = json.loads(text) if text else []
            if isinstance(adapters, dict):
                adapters = [adapters]
            for ad in adapters:
                name = ad.get('Name')
                if not name:
                    continue
                info = interfaces.setdefault(name, {
                    'name': name,
                    'type': 'unknown',
                    'speed_mbps': None,
                    'signal_strength': None,
                    'ipv4': [],
                    'ipv6': []
                })
                medium = str(ad.get('NdisPhysicalMedium', '')).lower()
                if 'wireless' in medium:
                    info['type'] = 'wireless'
                elif '802.3' in medium or 'ethernet' in medium:
                    info['type'] = 'wired'
                link_speed = str(ad.get('LinkSpeed', '')).strip()
                m = re.search(r'([0-9]+(?:\.[0-9]+)?)\s*([GMK]?)bps', link_speed, re.IGNORECASE)
                if m:
                    value = float(m.group(1))
                    unit = m.group(2).upper()
                    if unit == 'G':
                        info['speed_mbps'] = round(value * 1000, 2)
                    elif unit == 'K':
                        info['speed_mbps'] = round(value / 1000, 3)
                    else:
                        info['speed_mbps'] = round(value, 2)
        except Exception:
            pass

        # Wireless signal (best effort)
        try:
            wlan = self._run_command(['netsh', 'wlan', 'show', 'interfaces'])
            current = None
            for raw in wlan.splitlines():
                line = raw.strip()
                if line.lower().startswith('name') and ':' in line:
                    current = line.split(':', 1)[1].strip()
                    interfaces.setdefault(current, {
                        'name': current,
                        'type': 'wireless',
                        'speed_mbps': None,
                        'signal_strength': None,
                        'ipv4': [],
                        'ipv6': []
                    })
                    interfaces[current]['type'] = 'wireless'
                elif current and line.lower().startswith('signal') and ':' in line:
                    interfaces[current]['signal_strength'] = line.split(':', 1)[1].strip()
        except Exception:
            pass

        # Routes
        try:
            text = self._run_command(['route', 'print', '-4'])
            in_ipv4_table = False
            for raw in text.splitlines():
                line = raw.strip()
                if line.startswith('IPv4 Route Table'):
                    in_ipv4_table = True
                if in_ipv4_table and re.match(r'^\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+', line):
                    parts = re.split(r'\s+', line)
                    if len(parts) >= 4:
                        routes.append({
                            'destination': parts[0],
                            'mask': parts[1],
                            'gateway': parts[2],
                            'interface_ip': parts[3],
                            'metric': parts[4] if len(parts) > 4 else None
                        })
        except Exception:
            pass

        return {
            'interfaces': self._filter_addressed_interfaces(interfaces),
            'routes': routes
        }

    def _collect_linux_host_info(self) -> dict:
        interfaces = {}
        routes = []

        try:
            text = self._run_command(['ip', '-o', 'link', 'show'])
            for raw in text.splitlines():
                m = re.match(r'^\d+:\s+([^:]+):', raw)
                if not m:
                    continue
                name = m.group(1).split('@')[0]
                interfaces[name] = {
                    'name': name,
                    'type': 'wireless' if name.startswith('wl') else 'wired',
                    'speed_mbps': None,
                    'signal_strength': None,
                    'ipv4': [],
                    'ipv6': []
                }
        except Exception as e:
            if self._looks_like_permission_error(str(e)):
                raise PermissionError(str(e))

        # IP addresses
        try:
            text4 = self._run_command(['ip', '-o', '-4', 'addr', 'show'])
            for raw in text4.splitlines():
                parts = raw.split()
                if len(parts) >= 4:
                    name = parts[1]
                    ip = parts[3]
                    interfaces.setdefault(name, {'name': name, 'type': 'unknown', 'speed_mbps': None, 'signal_strength': None, 'ipv4': [], 'ipv6': []})
                    interfaces[name]['ipv4'].append(ip)
        except Exception:
            pass

        try:
            text6 = self._run_command(['ip', '-o', '-6', 'addr', 'show'])
            for raw in text6.splitlines():
                parts = raw.split()
                if len(parts) >= 4:
                    name = parts[1]
                    ip = parts[3]
                    interfaces.setdefault(name, {'name': name, 'type': 'unknown', 'speed_mbps': None, 'signal_strength': None, 'ipv4': [], 'ipv6': []})
                    interfaces[name]['ipv6'].append(ip)
        except Exception:
            pass

        # Interface speed from sysfs (best effort)
        for name, info in interfaces.items():
            speed_file = f'/sys/class/net/{name}/speed'
            try:
                if os.path.exists(speed_file):
                    with open(speed_file, 'r', encoding='utf-8', errors='ignore') as f:
                        raw = f.read().strip()
                        if raw.isdigit() and int(raw) > 0:
                            info['speed_mbps'] = int(raw)
            except Exception as e:
                if self._looks_like_permission_error(str(e)):
                    raise PermissionError(str(e))

        # Wireless signal from /proc/net/wireless (best effort)
        try:
            if os.path.exists('/proc/net/wireless'):
                with open('/proc/net/wireless', 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()[2:]
                    for line in lines:
                        if ':' not in line:
                            continue
                        iface, rest = line.split(':', 1)
                        iface = iface.strip()
                        parts = rest.split()
                        if len(parts) >= 3:
                            quality = parts[1].strip('.')
                            interfaces.setdefault(iface, {'name': iface, 'type': 'wireless', 'speed_mbps': None, 'signal_strength': None, 'ipv4': [], 'ipv6': []})
                            interfaces[iface]['type'] = 'wireless'
                            interfaces[iface]['signal_strength'] = f'{quality}/70'
        except Exception:
            pass

        # Routes
        try:
            text = self._run_command(['ip', 'route', 'show'])
            for raw in text.splitlines():
                line = raw.strip()
                if not line:
                    continue
                route = {'raw': line}
                m_dst = re.match(r'^(default|[0-9./]+)', line)
                if m_dst:
                    route['destination'] = m_dst.group(1)
                m_via = re.search(r'\svia\s+([^\s]+)', line)
                if m_via:
                    route['gateway'] = m_via.group(1)
                m_dev = re.search(r'\sdev\s+([^\s]+)', line)
                if m_dev:
                    route['interface'] = m_dev.group(1)
                routes.append(route)
        except Exception:
            pass

        return {
            'interfaces': self._filter_addressed_interfaces(interfaces),
            'routes': routes
        }

    def collect_host_network_info(self) -> Optional[dict]:
        """Collect host network information once per test cycle.

        If collection fails due to permissions, disable further attempts until restart.
        """
        if self._host_info_permission_denied:
            return None

        snapshot = {
            'timestamp': datetime.utcnow().isoformat(),
            'platform': platform.system(),
            'hostname': socket.gethostname(),
            'uptime_sec': None,
            'memory': {
                'used_bytes': None,
                'available_bytes': None,
                'total_bytes': None,
                'page_file_used_bytes': None,
                'page_file_available_bytes': None,
                'page_file_total_bytes': None
            },
            'main_drive': {
                'mount': None,
                'used_bytes': None,
                'total_bytes': None,
                'available_bytes': None
            },
            'interfaces': [],
            'routes': [],
            'wan_ip': None
        }

        try:
            system = platform.system().lower()
            if system == 'windows':
                data = self._collect_windows_host_info()
            else:
                data = self._collect_linux_host_info()

            snapshot['interfaces'] = data.get('interfaces', [])
            snapshot['routes'] = data.get('routes', [])
            snapshot['wan_ip'] = self._collect_wan_ip()
            snapshot['uptime_sec'] = self._collect_uptime_seconds()
            snapshot['memory'] = self._collect_memory_info()
            snapshot['main_drive'] = self._collect_main_drive_info()
            return snapshot
        except PermissionError as e:
            logger.warning(f"Host network info collection disabled until restart (permission issue): {e}")
            self._host_info_permission_denied = True
            return None
        except Exception as e:
            if self._looks_like_permission_error(str(e)):
                logger.warning(f"Host network info collection disabled until restart (permission issue): {e}")
                self._host_info_permission_denied = True
                return None
            logger.debug(f"Host network info collection failed for this cycle: {e}")
            return None

    def _get_auth_headers(self) -> dict:
        """Build default headers for authenticated client requests."""
        headers = {
            'User-Agent': 'VaneMonitor-Client/1.0'
        }
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        return headers

    def prompt_for_credentials(self, force_reenter: bool = False):
        """Prompt interactively for client API credentials when missing."""
        if force_reenter:
            self.client_username = ''
            self.client_password = ''

        print("\n" + "=" * 60)
        print("  CLIENT AUTHENTICATION")
        print("=" * 60)
        print("\nEnter a server user with role 'client'.")
        print("This username becomes the client identity used with the server.\n")

        while not self.client_username:
            self.client_username = input("Client username: ").strip()
            if not self.client_username:
                print("❌ Username is required.\n")

        while not self.client_password:
            self.client_password = getpass.getpass("Client password: ").strip()
            if not self.client_password:
                print("❌ Password is required.\n")

    def authenticate_with_server(self) -> bool:
        """Authenticate with username/password and obtain an API key."""
        try:
            data = {
                'username': self.client_username,
                'password': self.client_password
            }

            json_data = json.dumps(data).encode('utf-8')
            req = urllib.request.Request(
                f"{self.server_url}/api/auth/token",
                data=json_data,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'VaneMonitor-Client/1.0'
                },
                method='POST'
            )

            with self._open_url(req, timeout=10) as response:
                if response.status != 200:
                    logger.error(f"Client auth failed with status: {response.status}")
                    return False

                payload = json.loads(response.read().decode('utf-8'))
                api_key = payload.get('api_key', '')
                if not api_key:
                    logger.error("Client auth response did not include an API key")
                    return False

                self.api_key = api_key
                if self.client_name != self.client_username:
                    logger.info(
                        "Using authenticated client identity '%s' instead of configured client name '%s'",
                        self.client_username, self.client_name
                    )
                self.client_name = self.client_username
                self.client_password = ''
                self._save_runtime_auth_state()
                logger.info("Successfully authenticated client and obtained API key")
                return True

        except urllib.error.HTTPError as e:
            logger.error(f"Client authentication rejected: {e}")
            return False
        except urllib.error.URLError as e:
            logger.error(f"Failed to authenticate with server: {e}")
            return False
        except Exception as e:
            logger.error(f"Error during client authentication: {e}")
            return False

    def ensure_authenticated(self, max_attempts: int = 3) -> bool:
        """Ensure the client has an API key before calling protected endpoints."""
        if self.api_key:
            return True

        for attempt in range(1, max_attempts + 1):
            force_reenter = attempt > 1 or not self.client_username or not self.client_password
            if force_reenter:
                self.prompt_for_credentials(force_reenter=attempt > 1)

            if self.authenticate_with_server():
                return True

            if attempt < max_attempts:
                logger.warning(f"Client authentication failed (attempt {attempt}/{max_attempts}). Please try again.")

        logger.error(f"Client authentication failed after {max_attempts} attempt(s)")
        return False
    
    def register_with_server(self) -> bool:
        """Register client with the server before starting tests"""
        try:
            data = {
                'client_name': self.client_name
            }
            
            json_data = json.dumps(data).encode('utf-8')
            
            status, response_body = self._perform_authenticated_request(
                lambda: urllib.request.Request(
                    f"{self.server_url}/api/register",
                    data=json_data,
                    headers={
                        'Content-Type': 'application/json',
                        **self._get_auth_headers()
                    },
                    method='POST'
                ),
                timeout=10
            )
            if status == 200:
                result = json.loads(response_body.decode('utf-8'))
                logger.info(f"Successfully registered with server: {result.get('message', 'OK')}")
                self.registered = True
                return True

            logger.error(f"Server registration failed with status: {status}")
            return False
                    
        except urllib.error.HTTPError as e:
            logger.error(f"Server registration failed with HTTP error: {e}")
            return False
        except urllib.error.URLError as e:
            logger.error(f"Failed to register with server: {e}")
            return False
        except Exception as e:
            logger.error(f"Error during registration: {e}")
            return False
    
    def send_results(self, results: list, host_network_info: Optional[dict] = None) -> bool:
        """Send test results to server"""
        if not results:
            return True

        payload: Optional[Dict[str, Any]] = None
        try:
            payload = self._prepare_submission_payload(
                results,
                host_network_info=host_network_info,
                run_serial=self._active_run_serial,
                run_started_at=self._active_run_started_at,
            )

            if not self._flush_pending_submissions():
                self._queue_submission(payload)
                return False

            if self._submit_payload(payload):
                return True

            self._queue_submission(payload)
            return False
        except urllib.error.HTTPError as e:
            logger.warning(f"Server rejected result submission: {e}")
            if payload is not None and e.code >= 500:
                self._queue_submission(payload)
            return False
        except urllib.error.URLError as e:
            logger.warning(f"Failed to send results to server: {e}")
            if payload is not None:
                self._queue_submission(payload)
            return False
        except Exception as e:
            logger.warning(f"Error sending results: {e}")
            if payload is not None:
                self._queue_submission(payload)
            return False
    
    def fetch_destinations(self) -> list:
        """Fetch enabled destinations from server (global + client-specific merged)"""
        try:
            # Pass client_name so the server returns global + this client's destinations
            from urllib.parse import quote
            url = f"{self.server_url}/api/destinations?client_name={quote(self.client_name)}"
            status, response_body = self._perform_authenticated_request(
                lambda: urllib.request.Request(
                    url,
                    headers=self._get_auth_headers()
                ),
                timeout=10
            )

            if status == 200:
                data = json.loads(response_body.decode('utf-8'))
                destinations = [d for d in data.get('destinations', []) if d.get('enabled')]
                logger.info(f"Fetched {len(destinations)} enabled destinations from server")
                return destinations

            logger.error(f"Server responded with status: {status}")
            return []
                    
        except urllib.error.HTTPError as e:
            logger.error(f"Failed to fetch destinations: {e}")
            return []
        except urllib.error.URLError as e:
            logger.warning(f"Failed to fetch destinations from server: {e}")
            logger.info("Falling back to config-based tests")
            return []
        except Exception as e:
            logger.error(f"Error fetching destinations: {e}")
            return []

    def fetch_dns_test_domains(self) -> list:
        """Fetch domains from dns_test_domains table via server API"""
        try:
            status, response_body = self._perform_authenticated_request(
                lambda: urllib.request.Request(
                    f"{self.server_url}/api/dns-test-domains",
                    headers=self._get_auth_headers()
                ),
                timeout=10
            )

            if status == 200:
                data = json.loads(response_body.decode('utf-8'))
                domains = [item.get('domain') for item in data.get('domains', []) if item.get('domain')]
                logger.info(f"Fetched {len(domains)} dns_test_domains entries from server")
                return domains

            logger.error(f"Server responded with status: {status} for dns-test-domains")
        except urllib.error.HTTPError as e:
            logger.warning(f"Failed to fetch dns_test_domains from server: {e}")
        except Exception as e:
            logger.warning(f"Failed to fetch dns_test_domains from server: {e}")

        # Fallback to configured DNS targets if server-side table is unavailable
        fallback_domains = self.config.get('client', 'tests', 'dns', 'targets', default=[])
        logger.info(f"Using fallback DNS domain list from config: {len(fallback_domains)} target(s)")
        return fallback_domains if isinstance(fallback_domains, list) else []
    
    def run_destination_tests(self, destination: dict, dns_test_domains: list = None) -> list:
        """Run tests for a specific destination"""
        results = []
        target = destination['target']
        name = destination['name']
        
        logger.info(f"Testing destination: {name} ({target})")
        
        # Ping test
        if destination.get('test_ping'):
            result = self.monitor.ping_test(target, count=4, timeout=5)
            results.append(result)
        
        # DNS test
        if destination.get('test_dns'):
            domains_to_resolve = dns_test_domains if isinstance(dns_test_domains, list) else []
            if not domains_to_resolve:
                logger.warning(f"[DNS TEST] No dns_test_domains available for resolver destination {name} ({target})")

            logger.info(f"[DNS TEST] Resolver {target} will resolve {len(domains_to_resolve)} domain(s)")
            for domain in domains_to_resolve:
                logger.info(f"[DNS TEST] Resolving {domain} using resolver {target}")
                result = self.monitor.dns_test(domain, target)
                results.append(result)
        
        # HTTP test
        if destination.get('test_http'):
            http_target = target if target.startswith('http://') else f"http://{target}"
            result = self.monitor.http_test(http_target)
            results.append(result)
        
        # HTTPS test
        if destination.get('test_https'):
            https_target = target if target.startswith('https://') else f"https://{target}"
            result = self.monitor.http_test(https_target)
            results.append(result)
        
        # Jitter test
        if destination.get('test_jitter'):
            result = self.monitor.jitter_test(target, count=10, timeout=5)
            results.append(result)
        
        # Traceroute test
        if destination.get('test_traceroute'):
            result = self.monitor.traceroute_test(target, max_hops=30)
            results.append(result)
        
        # Port scan test
        if destination.get('test_ports'):
            ports_str = destination['test_ports']
            if ports_str:
                try:
                    ports = [int(p.strip()) for p in ports_str.split(',') if p.strip()]
                    if ports:
                        result = self.monitor.port_scan_test(target, ports)
                        results.append(result)
                except ValueError:
                    logger.error(f"Invalid port configuration for {name}: {ports_str}")
        
        return results
    
    def run_tests(self):
        """Run all configured network tests"""
        logger.info("Running network tests...")

        try:
            loop_started_at = datetime.utcnow()
            self._active_run_started_at = loop_started_at.isoformat()
            self._active_run_serial = self._build_run_serial(loop_started_at)
            logger.info("Starting test loop run_serial=%s", self._active_run_serial)

            self._flush_pending_submissions()

            host_network_info = self.collect_host_network_info()

            # Try to fetch destinations from server
            destinations = self.fetch_destinations()

            if destinations:
                # Fetch DNS test domains once for all destinations
                dns_test_domains = self.fetch_dns_test_domains()

                # Test each destination and send results immediately
                for dest in destinations:
                    logger.info(f"Testing destination: {dest['name']} ({dest['target']})")

                    dest_results = self.run_destination_tests(dest, dns_test_domains=dns_test_domains)

                    # Send results immediately after each destination
                    if dest_results:
                        success_count = sum(1 for r in dest_results if r.get('success', False))
                        logger.info(f"Completed {len(dest_results)} tests for {dest['name']} ({success_count} successful)")
                        self.send_results(dest_results, host_network_info=host_network_info)
                    else:
                        logger.warning(f"No results for destination {dest['name']}")
            else:
                logger.warning("No destinations available from server")

            # L4S probe — runs at most once every l4s_interval seconds (default 10 min).
            # Excluded from the destinations loop because it saturates the link
            # for ~10 seconds; running it per-destination would skew RTT results.
            if self.enable_l4s_testing:
                now = time.time()
                if now - self._last_l4s_run >= self.l4s_interval:
                    self._run_l4s_probe_cycle(host_network_info)
                    self._last_l4s_run = now
                else:
                    remaining = int(self.l4s_interval - (now - self._last_l4s_run))
                    logger.debug(f"L4S probe skipped — next run in {remaining}s")

        except Exception as e:
            logger.error(f"Error running tests: {e}", exc_info=True)
        finally:
            self._active_run_serial = None
            self._active_run_started_at = None

    def _run_l4s_probe_cycle(self, host_network_info: Optional[dict]) -> None:
        """Run the L4S / ECN responsiveness probe and submit the result."""
        try:
            try:
                from client.l4s_probe import run_l4s_probe  # type: ignore[import-not-found]
            except ModuleNotFoundError:
                from l4s_probe import run_l4s_probe
            logger.info(f"Running L4S probe against {self.l4s_target}...")
            result = run_l4s_probe(target_host=self.l4s_target)
            logger.info(
                "L4S probe: supported=%s ecn=%s rpm=%s working_lat=%sms",
                result.get("l4s_supported"),
                result.get("ecn_path_status"),
                result.get("rpm_score"),
                result.get("working_latency_ms"),
            )
            self.send_results([result], host_network_info=host_network_info)
        except Exception as e:
            logger.error(f"L4S probe failed: {e}", exc_info=True)
    
    def start(self):
        """Start the client with scheduled testing"""
        logger.info(f"Starting network monitoring client: {self.client_name}")

        if not self.ensure_authenticated():
            logger.error("Client authentication failed. Exiting client mode.")
            self.running = False
            return
        
        # Register with server before starting tests
        logger.info("Registering with server...")
        if not self.register_with_server():
            logger.error("Failed to register with server. Tests will still run, but server may not accept results.")
        
        self.running = True
        
        try:
            while self.running:
                self.run_tests()
                
                # Wait for next test interval
                logger.info(f"Waiting {self.test_interval} seconds until next test...")
                time.sleep(self.test_interval)
                
        except KeyboardInterrupt:
            logger.info("Client stopping...")
            self.running = False
        except Exception as e:
            logger.error(f"Client error: {e}", exc_info=True)
            self.running = False
    
    def stop(self):
        """Stop the client"""
        logger.info("Stopping client...")
        self.running = False
