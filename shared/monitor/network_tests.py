"""
Network testing functionality.
Performs various network tests: ping, HTTP, DNS, traceroute.
"""
import asyncio
import importlib
import ipaddress
import logging
import platform
import re
import socket
import statistics
import subprocess
import threading
import time
from datetime import datetime
from typing import Any, Dict, List

from shared.monitor.asn_lookup import ASNLookup

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """Performs various network monitoring tests."""

    def __init__(self, enable_asn_lookup: bool = True):
        self.platform = platform.system().lower()
        self.asn_lookup = ASNLookup(use_whois=True) if enable_asn_lookup else None

    def _build_route_signature(self, parsed_hops: List[Dict[str, Any]]) -> str:
        if not parsed_hops:
            return ''

        segments = []
        for index, hop in enumerate(parsed_hops):
            hop_number = hop.get('hop', index + 1)
            routers = hop.get('routers', []) or []
            token = ','.join(routers) if routers else '*'
            segments.append(f'{hop_number}:{token}')

        while segments and segments[-1].endswith(':*'):
            segments.pop()

        return '|'.join(segments)

    def ping_test(self, target: str, count: int = 4, timeout: int = 5) -> Dict[str, Any]:
        logger.info('Pinging %s...', target)

        try:
            if self.platform == 'windows':
                param = '-n'
                timeout_param = '-w'
                timeout_ms = timeout * 1000
            else:
                param = '-c'
                timeout_param = '-W'
                timeout_ms = timeout

            cmd = ['ping', param, str(count), timeout_param, str(timeout_ms), target]

            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout * count + 5,
            )
            end_time = time.time()

            output = result.stdout
            success = result.returncode == 0
            packets_sent = count
            packets_received = 0
            min_rtt = None
            avg_rtt = None
            max_rtt = None

            if success:
                rtts = []
                for line in output.split('\n'):
                    if 'time=' in line.lower() or 'zeit=' in line.lower():
                        try:
                            time_part = line.lower().split('time=')[-1] if 'time=' in line.lower() else line.lower().split('zeit=')[-1]
                            rtt_str = time_part.split()[0].replace('ms', '').replace('<', '')
                            rtts.append(float(rtt_str))
                            packets_received += 1
                        except (ValueError, IndexError):
                            continue

                if rtts:
                    min_rtt = min(rtts)
                    avg_rtt = statistics.mean(rtts)
                    max_rtt = max(rtts)

            packet_loss = ((packets_sent - packets_received) / packets_sent) * 100 if packets_sent > 0 else 100

            return {
                'test_type': 'ping',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': success,
                'packets_sent': packets_sent,
                'packets_received': packets_received,
                'packet_loss_pct': round(packet_loss, 2),
                'min_rtt_ms': round(min_rtt, 2) if min_rtt else None,
                'avg_rtt_ms': round(avg_rtt, 2) if avg_rtt else None,
                'max_rtt_ms': round(max_rtt, 2) if max_rtt else None,
                'duration_sec': round(end_time - start_time, 2),
            }
        except subprocess.TimeoutExpired:
            logger.error('Ping to %s timed out', target)
            return {
                'test_type': 'ping',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'error': 'Timeout',
                'packets_sent': count,
                'packets_received': 0,
                'packet_loss_pct': 100.0,
            }
        except Exception as exc:
            logger.error('Ping to %s failed: %s', target, exc)
            return {
                'test_type': 'ping',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'error': str(exc),
            }

    def packet_loss_ping_test(self, target: str, count: int = 100, timeout: float = 1.0,
                              interval: float = 0.05) -> Dict[str, Any]:
        logger.info('Running packet-loss ping test to %s with %s probes...', target, count)
        start_time = time.time()

        try:
            aioping = importlib.import_module('aioping')

            async def _run_aioping() -> List[float]:
                samples: List[float] = []
                for _ in range(count):
                    try:
                        delay = await aioping.ping(target, timeout=timeout)
                        samples.append(float(delay) * 1000.0)
                    except TimeoutError:
                        pass
                    except Exception:
                        pass

                    if interval > 0:
                        await asyncio.sleep(interval)
                return samples

            rtts = asyncio.run(_run_aioping())
            packets_sent = count
            packets_received = len(rtts)

            min_rtt = min(rtts) if rtts else None
            avg_rtt = statistics.mean(rtts) if rtts else None
            max_rtt = max(rtts) if rtts else None
            packet_loss = ((packets_sent - packets_received) / packets_sent) * 100 if packets_sent > 0 else 100.0

            return {
                'test_type': 'ping',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': packets_received > 0,
                'packets_sent': packets_sent,
                'packets_received': packets_received,
                'packet_loss_pct': round(packet_loss, 2),
                'has_packet_loss': packet_loss > 0,
                'min_rtt_ms': round(min_rtt, 2) if min_rtt is not None else None,
                'avg_rtt_ms': round(avg_rtt, 2) if avg_rtt is not None else None,
                'max_rtt_ms': round(max_rtt, 2) if max_rtt is not None else None,
                'duration_sec': round(time.time() - start_time, 2),
                'ping_method': 'aioping',
                'sample_size': count,
            }
        except ImportError:
            logger.warning('aioping is not installed, falling back to system ping command')
            result = self.ping_test(target=target, count=count, timeout=max(1, int(timeout)))
            result['has_packet_loss'] = result.get('packet_loss_pct', 100.0) > 0
            result['ping_method'] = 'system_ping_fallback'
            result['sample_size'] = count
            return result
        except Exception as exc:
            logger.error('High-sample ping test to %s failed: %s', target, exc)
            return {
                'test_type': 'ping',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'error': str(exc),
                'packets_sent': count,
                'packets_received': 0,
                'packet_loss_pct': 100.0,
                'has_packet_loss': True,
                'ping_method': 'aioping',
                'sample_size': count,
                'duration_sec': round(time.time() - start_time, 2),
            }

    def http_test(self, target: str, timeout: int = 10) -> Dict[str, Any]:
        logger.info('Testing HTTP(S) %s...', target)

        try:
            import urllib.error
            import urllib.request

            start_time = time.time()
            req = urllib.request.Request(target, headers={'User-Agent': 'VaneMonitor/1.0'})

            try:
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    status_code = response.status
                    response_time = time.time() - start_time
                    content_length = len(response.read())
                    return {
                        'test_type': 'http',
                        'target': target,
                        'timestamp': datetime.utcnow().isoformat(),
                        'success': True,
                        'status_code': status_code,
                        'response_time_sec': round(response_time, 3),
                        'content_length_bytes': content_length,
                    }
            except urllib.error.HTTPError as exc:
                response_time = time.time() - start_time
                return {
                    'test_type': 'http',
                    'target': target,
                    'timestamp': datetime.utcnow().isoformat(),
                    'success': False,
                    'status_code': exc.code,
                    'response_time_sec': round(response_time, 3),
                    'error': str(exc),
                }
        except Exception as exc:
            logger.error('HTTP test to %s failed: %s', target, exc)
            return {
                'test_type': 'http',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'error': str(exc),
            }

    def dns_test(self, target: str, dns_server: str = None) -> Dict[str, Any]:
        logger.info('Testing DNS resolution for %s using %s...', target, dns_server or 'default resolver')

        try:
            start_time = time.time()
            ips = []

            if dns_server and dns_server != 'default':
                cmd = ['nslookup', target, dns_server]
                nslookup_result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                output = (nslookup_result.stdout or '') + '\n' + (nslookup_result.stderr or '')

                def _extract_ip_candidates(text: str) -> List[str]:
                    candidates = []
                    for token in re.split(r'\s+', text.replace(',', ' ').replace(';', ' ')):
                        cleaned = token.strip().strip('[]()')
                        if not cleaned:
                            continue
                        try:
                            ip_obj = ipaddress.ip_address(cleaned)
                            if cleaned not in candidates:
                                candidates.append(str(ip_obj))
                        except ValueError:
                            continue
                    return candidates

                answer_section_started = False
                answer_ips = []
                for line in output.splitlines():
                    stripped = line.strip()
                    lowered = stripped.lower()

                    if lowered.startswith('non-authoritative answer') or lowered.startswith('authoritative answers'):
                        answer_section_started = True
                        continue

                    if lowered.startswith('name:'):
                        answer_section_started = True
                        continue

                    if answer_section_started:
                        if lowered.startswith(('address:', 'addresses:')):
                            answer_ips.extend(_extract_ip_candidates(stripped.split(':', 1)[1]))
                        else:
                            answer_ips.extend(_extract_ip_candidates(stripped))

                ips = answer_ips or _extract_ip_candidates(output)
            else:
                addr_info = socket.getaddrinfo(target, None)
                seen = set()
                for info in addr_info:
                    ip = info[4][0]
                    if ip not in seen:
                        seen.add(ip)
                        ips.append(ip)

            resolution_time = time.time() - start_time
            success = len(ips) > 0
            return {
                'test_type': 'dns',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': success,
                'dns_server': dns_server or 'default',
                'resolved_ips': ips,
                'response_time_sec': round(resolution_time, 3),
                'records_found': len(ips),
            }
        except Exception as exc:
            logger.error('DNS test for %s failed: %s', target, exc)
            return {
                'test_type': 'dns',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'dns_server': dns_server or 'default',
                'error': str(exc),
            }

    def traceroute_test(self, target: str, max_hops: int = 30) -> Dict[str, Any]:
        logger.info('Running traceroute to %s...', target)

        try:
            if self.platform == 'windows':
                cmd = ['tracert', '-h', str(max_hops), target]
            else:
                traceroute_cmd = 'traceroute'
                if platform.system().lower() == 'linux':
                    traceroute_cmd = 'tracepath' if subprocess.run(['which', 'tracepath'], capture_output=True).returncode == 0 else 'traceroute'

                if traceroute_cmd == 'tracepath':
                    cmd = ['tracepath', target]
                else:
                    cmd = [traceroute_cmd, '-m', str(max_hops), target]

            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            end_time = time.time()
            output = result.stdout

            hops = []
            parsed_hops = []
            if result.returncode == 0 or output:
                for line in output.split('\n'):
                    line = line.strip()
                    if not line:
                        continue

                    hops.append(line)

                    hop_match = re.match(r'^(\d+)\s+(.*)$', line)
                    if not hop_match:
                        continue

                    hop_num = int(hop_match.group(1))
                    remainder = hop_match.group(2)
                    routers = []

                    for ip_match in re.finditer(r'(\d{1,3}(?:\.\d{1,3}){3})', remainder):
                        routers.append(ip_match.group(1))

                    if not routers and '*' in remainder:
                        parsed_hops.append({'hop': hop_num, 'routers': [], 'timed_out': True})
                        continue

                    parsed_hops.append({'hop': hop_num, 'routers': routers, 'timed_out': False})

                route_signature = self._build_route_signature(parsed_hops)
                asn_enriched_hops = []
                if self.asn_lookup:
                    for hop in parsed_hops:
                        enriched = dict(hop)
                        enriched['asn_info'] = self.asn_lookup.enrich_routers(hop.get('routers', []))
                        asn_enriched_hops.append(enriched)

                return {
                    'test_type': 'traceroute',
                    'target': target,
                    'timestamp': datetime.utcnow().isoformat(),
                    'success': True,
                    'hops': hops,
                    'hop_count': len(hops),
                    'duration_sec': round(end_time - start_time, 2),
                    'route_signature': route_signature,
                    'parsed_hops': parsed_hops,
                    'asn_enriched_hops': asn_enriched_hops,
                }

            return {
                'test_type': 'traceroute',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'error': 'Traceroute failed',
            }
        except Exception as exc:
            logger.error('Traceroute to %s failed: %s', target, exc)
            return {
                'test_type': 'traceroute',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'error': str(exc),
            }

    def jitter_test(self, target: str, count: int = 10, timeout: int = 5) -> Dict[str, Any]:
        """
        Perform jitter test (variation in ping latency).
        All individual pings are fired concurrently via a thread pool so the
        total wall-clock time is roughly equal to one RTT instead of count x RTT.
        """
        logger.info(f"Testing jitter to {target}...")

        def _single_ping():
            """Send one ping and return the RTT in ms, or None on failure."""
            if self.platform == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), target]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), target]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout + 2
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'time=' in line.lower() or 'zeit=' in line.lower():
                            try:
                                time_part = (
                                    line.lower().split('time=')[-1]
                                    if 'time=' in line.lower()
                                    else line.lower().split('zeit=')[-1]
                                )
                                rtt_str = time_part.split()[0].replace('ms', '').replace('<', '')
                                return float(rtt_str)
                            except (ValueError, IndexError):
                                continue
            except Exception:
                pass
            return None

        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            rtts: List[float] = []
            with ThreadPoolExecutor(max_workers=count) as executor:
                futures = [executor.submit(_single_ping) for _ in range(count)]
                for fut in as_completed(futures):
                    val = fut.result()
                    if val is not None:
                        rtts.append(val)

            if len(rtts) >= 2:
                import statistics as _stats
                avg_rtt = _stats.mean(rtts)
                jitter = _stats.stdev(rtts)
                return {
                    'test_type': 'jitter',
                    'target': target,
                    'timestamp': datetime.utcnow().isoformat(),
                    'success': True,
                    'sample_count': len(rtts),
                    'avg_rtt_ms': round(avg_rtt, 2),
                    'jitter_ms': round(jitter, 2),
                    'min_rtt_ms': round(min(rtts), 2),
                    'max_rtt_ms': round(max(rtts), 2),
                }
            else:
                return {
                    'test_type': 'jitter',
                    'target': target,
                    'timestamp': datetime.utcnow().isoformat(),
                    'success': False,
                    'error': 'Insufficient samples collected',
                }
        except Exception as e:
            logger.error(f"Jitter test to {target} failed: {e}")
            return {
                'test_type': 'jitter',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'error': str(e),
            }

    def port_scan_test(self, target: str, ports: List[int], timeout: int = 2) -> Dict[str, Any]:
        """Test if specific ports are open on target."""
        logger.info(f"Scanning ports {ports} on {target}...")

        def _check_port(port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                start = time.time()
                err = sock.connect_ex((target, port))
                elapsed = time.time() - start
                sock.close()
                return ('open', port, elapsed) if err == 0 else ('closed', port, elapsed)
            except Exception as exc:
                logger.debug(f"Error scanning port {port}: {exc}")
                return ('closed', port, 0.0)

        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            open_ports = []
            closed_ports = []
            max_workers = min(len(ports), 50)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_check_port, p): p for p in ports}
                for fut in as_completed(futures):
                    status, port, elapsed = fut.result()
                    if status == 'open':
                        open_ports.append({'port': port, 'response_time_sec': round(elapsed, 3)})
                    else:
                        closed_ports.append(port)

            return {
                'test_type': 'port_scan',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': True,
                'ports_tested': len(ports),
                'open_ports': open_ports,
                'closed_ports': closed_ports,
                'open_count': len(open_ports),
            }
        except Exception as e:
            logger.error(f"Port scan to {target} failed: {e}")
            return {
                'test_type': 'port_scan',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'error': str(e),
            }

    def run_test(self, test_type: str, target: str, **kwargs) -> Dict[str, Any]:
        if test_type == 'ping':
            return self.ping_test(target, **kwargs)
        if test_type == 'http':
            return self.http_test(target, **kwargs)
        if test_type == 'dns':
            return self.dns_test(target, **kwargs)
        if test_type == 'traceroute':
            return self.traceroute_test(target, **kwargs)
        if test_type == 'jitter':
            return self.jitter_test(target, **kwargs)
        if test_type == 'port_scan':
            return self.port_scan_test(target, **kwargs)

        return {
            'test_type': test_type,
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'error': f'Unknown test type: {test_type}',
        }