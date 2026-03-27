"""
Network monitoring client
Runs scheduled tests and sends results to server
"""
import time
import logging
import json
import os
import ssl
import urllib.request
import urllib.error
from typing import Optional
from config import Config
from monitor.network_tests import NetworkMonitor

logger = logging.getLogger(__name__)


class NetworkClient:
    """Client that performs network tests and reports to server"""
    
    def __init__(self, config_file: Optional[str] = None, server_url: Optional[str] = None):
        """Initialize the network client"""
        
        # Try to load simplified client_config.json first, fallback to config.json
        if config_file is None:
            if os.path.exists('client_config.json'):
                config_file = 'client_config.json'
                logger.info("Using client_config.json for configuration")
        
        # Load configuration
        if config_file and config_file.endswith('client_config.json'):
            # Simplified config file
            try:
                with open(config_file, 'r') as f:
                    client_config = json.load(f)
                self.config = None
                self.client_name = client_config.get('client_name', 'unknown_client')
                self.server_url = server_url or client_config.get('server_url', 'http://localhost:5000')
                self.test_interval = client_config.get('test_interval', 60)
                self.verify_ssl = client_config.get('verify_ssl', True)
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
        
        self.monitor = NetworkMonitor()
        self.running = False
        self.registered = False
        self.api_key = None
        self._config_file = config_file

        # Build SSL context for server communication
        self._ssl_context = self._build_ssl_context()

        # Load saved API key if available
        self._load_api_key()
        
        logger.info(f"Client initialized: {self.client_name}")
        logger.info(f"Server URL: {self.server_url}")
        logger.info(f"Test interval: {self.test_interval} seconds")
        logger.info(f"SSL verification: {'enabled' if self.verify_ssl else 'DISABLED (self-signed)'}")

    # ---------- SSL helpers ----------

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Return an SSL context used by all urllib calls.

        When *verify_ssl* is False (typical for self-signed certs),
        certificate verification is skipped.
        """
        if self.verify_ssl:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _urlopen(self, req, timeout=10):
        """Wrapper around urllib.request.urlopen that injects the SSL context."""
        return urllib.request.urlopen(req, timeout=timeout, context=self._ssl_context)

    # ---------- API-key persistence ----------

    @property
    def _api_key_path(self):
        return os.path.join(os.path.dirname(self._config_file or 'client_config.json') or '.', '.vane_api_key')

    def _load_api_key(self):
        """Load a previously obtained API key from disk."""
        try:
            if os.path.exists(self._api_key_path):
                with open(self._api_key_path, 'r') as f:
                    self.api_key = f.read().strip()
                if self.api_key:
                    logger.info("Loaded saved API key")
        except Exception as e:
            logger.warning(f"Could not load API key: {e}")

    def _save_api_key(self, key: str):
        """Persist the API key to disk."""
        try:
            with open(self._api_key_path, 'w') as f:
                f.write(key)
            self.api_key = key
            logger.info("API key saved to disk")
        except Exception as e:
            logger.error(f"Failed to save API key: {e}")

    def _auth_headers(self) -> dict:
        """Return headers dict that includes the API key if available."""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'VaneMonitor-Client/1.0'
        }
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        return headers

    def authenticate_with_server(self) -> bool:
        """Authenticate with server using username/password and obtain an API key.
        Prompts user interactively for credentials on first run."""
        if self.api_key:
            # Verify the key is still valid by hitting a lightweight endpoint
            # Use /api/destinations because it allows the 'client' role
            try:
                req = urllib.request.Request(
                    f"{self.server_url}/api/destinations",
                    headers=self._auth_headers()
                )
                with self._urlopen(req, timeout=10) as resp:
                    if resp.status == 200:
                        logger.info("Existing API key is valid")
                        return True
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    logger.warning("Saved API key is no longer valid, re-authenticating...")
                    self.api_key = None
                else:
                    raise
            except Exception:
                pass

        # Interactive prompt
        print("\n" + "="*60)
        print("  CLIENT AUTHENTICATION")
        print("="*60)
        print("\nEnter server credentials (a user with 'client' or 'admin' role):\n")

        username = input("Username: ").strip()
        import getpass
        password = getpass.getpass("Password: ")

        try:
            data = json.dumps({'username': username, 'password': password}).encode('utf-8')
            req = urllib.request.Request(
                f"{self.server_url}/api/auth/token",
                data=data,
                headers={'Content-Type': 'application/json', 'User-Agent': 'VaneMonitor-Client/1.0'},
                method='POST'
            )
            with self._urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                if result.get('success') and result.get('api_key'):
                    self._save_api_key(result['api_key'])
                    print("✅ Authenticated successfully. API key saved.\n" + "="*60 + "\n")
                    return True
                else:
                    print(f"❌ Authentication failed: {result.get('error', 'Unknown error')}\n")
                    return False
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace')
            print(f"❌ Authentication failed (HTTP {e.code}): {body}\n")
            return False
        except Exception as e:
            print(f"❌ Authentication error: {e}\n")
            return False
    
    def register_with_server(self) -> bool:
        """Register client with the server before starting tests"""
        try:
            data = {
                'client_name': self.client_name
            }
            
            json_data = json.dumps(data).encode('utf-8')
            
            req = urllib.request.Request(
                f"{self.server_url}/api/register",
                data=json_data,
                headers=self._auth_headers(),
                method='POST'
            )
            
            with self._urlopen(req, timeout=10) as response:
                if response.status == 200:
                    result = json.loads(response.read().decode('utf-8'))
                    logger.info(f"Successfully registered with server: {result.get('message', 'OK')}")
                    self.registered = True
                    return True
                else:
                    logger.error(f"Server registration failed with status: {response.status}")
                    return False
                    
        except urllib.error.URLError as e:
            logger.error(f"Failed to register with server: {e}")
            return False
        except Exception as e:
            logger.error(f"Error during registration: {e}")
            return False
    
    def send_results(self, results: list) -> bool:
        """Send test results to server"""
        try:
            data = {
                'client_id': self.client_name,  # Server still uses 'client_id' field
                'results': results
            }
            
            json_data = json.dumps(data).encode('utf-8')
            
            req = urllib.request.Request(
                f"{self.server_url}/api/submit",
                data=json_data,
                headers=self._auth_headers(),
                method='POST'
            )
            
            with self._urlopen(req, timeout=30) as response:
                if response.status == 200:
                    logger.info(f"Successfully sent {len(results)} test results to server")
                    return True
                else:
                    logger.error(f"Server responded with status: {response.status}")
                    return False
                    
        except urllib.error.URLError as e:
            logger.error(f"Failed to send results to server: {e}")
            return False
        except Exception as e:
            logger.error(f"Error sending results: {e}")
            return False
    
    def fetch_destinations(self) -> list:
        """Fetch enabled destinations from server"""
        try:
            req = urllib.request.Request(
                f"{self.server_url}/api/destinations",
                headers=self._auth_headers()
            )
            
            with self._urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    destinations = [d for d in data.get('destinations', []) if d.get('enabled')]
                    logger.info(f"Fetched {len(destinations)} enabled destinations from server")
                    return destinations
                else:
                    logger.error(f"Server responded with status: {response.status}")
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
            req = urllib.request.Request(
                f"{self.server_url}/api/dns-test-domains",
                headers=self._auth_headers()
            )

            with self._urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    domains = [item.get('domain') for item in data.get('domains', []) if item.get('domain')]
                    logger.info(f"Fetched {len(domains)} dns_test_domains entries from server")
                    return domains
                else:
                    logger.error(f"Server responded with status: {response.status} for dns-test-domains")
        except Exception as e:
            logger.warning(f"Failed to fetch dns_test_domains from server: {e}")

        # Fallback to configured DNS targets if server-side table is unavailable
        if self.config:
            fallback_domains = self.config.get('client', 'tests', 'dns', 'targets', default=[])
        else:
            fallback_domains = []
        logger.info(f"Using fallback DNS domain list from config: {len(fallback_domains)} target(s)")
        return fallback_domains if isinstance(fallback_domains, list) else []

    def run_destination_tests(self, destination: dict, dns_test_domains: list = None) -> list:
        """Run all enabled tests for a destination concurrently.

        Independent test types (ping, HTTP, HTTPS, jitter, traceroute, port scan,
        and individual DNS domain lookups) are submitted to a thread pool and
        executed in parallel so that the slowest test (usually traceroute) no
        longer serialises everything else.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        target = destination['target']
        name = destination['name']

        logger.info(f"Testing destination: {name} ({target})")

        futures_map = {}

        with ThreadPoolExecutor(max_workers=16) as executor:
            # --- Packet-loss / ping test ---
            if destination.get('test_ping'):
                futures_map[executor.submit(
                    self.monitor.packet_loss_ping_test, target, 100, 1.0, 0.05
                )] = 'ping'

            # --- HTTP test ---
            if destination.get('test_http'):
                http_target = target if target.startswith('http://') else f"http://{target}"
                futures_map[executor.submit(self.monitor.http_test, http_target)] = 'http'

            # --- HTTPS test ---
            if destination.get('test_https'):
                https_target = target if target.startswith('https://') else f"https://{target}"
                futures_map[executor.submit(self.monitor.http_test, https_target)] = 'https'

            # --- Jitter test ---
            if destination.get('test_jitter'):
                futures_map[executor.submit(
                    self.monitor.jitter_test, target, 10, 5
                )] = 'jitter'

            # --- Traceroute test ---
            if destination.get('test_traceroute'):
                futures_map[executor.submit(
                    self.monitor.traceroute_test, target, 30
                )] = 'traceroute'

            # --- Port scan test ---
            if destination.get('test_ports'):
                ports_str = destination['test_ports']
                if ports_str:
                    try:
                        ports = [int(p.strip()) for p in ports_str.split(',') if p.strip()]
                        if ports:
                            futures_map[executor.submit(
                                self.monitor.port_scan_test, target, ports
                            )] = 'port_scan'
                    except ValueError:
                        logger.error(f"Invalid port configuration for {name}: {ports_str}")

            # --- DNS tests (one concurrent lookup per domain) ---
            if destination.get('test_dns'):
                domains_to_resolve = dns_test_domains if isinstance(dns_test_domains, list) else []
                if not domains_to_resolve:
                    logger.warning(
                        f"[DNS TEST] No dns_test_domains available for resolver destination {name} ({target})"
                    )
                logger.info(f"[DNS TEST] Resolver {target} will resolve {len(domains_to_resolve)} domain(s)")
                for domain in domains_to_resolve:
                    futures_map[executor.submit(
                        self.monitor.dns_test, domain, target
                    )] = f'dns:{domain}'

            results = []
            for fut in as_completed(futures_map):
                test_label = futures_map[fut]
                try:
                    result = fut.result()
                    if result:
                        results.append(result)
                except Exception as exc:
                    logger.error(f"Test '{test_label}' for {name} ({target}) raised: {exc}")

        return results
    
    def _run_and_send_destination(self, dest: dict, dns_test_domains: list) -> None:
        """Run all tests for *dest* and immediately send results to the server."""
        dest_results = self.run_destination_tests(dest, dns_test_domains=dns_test_domains)
        if dest_results:
            success_count = sum(1 for r in dest_results if r.get('success', False))
            logger.info(
                f"Completed {len(dest_results)} tests for {dest['name']} "
                f"({success_count} successful)"
            )
            self.send_results(dest_results)
        else:
            logger.warning(f"No results for destination {dest['name']}")

    def run_tests(self):
        """Run all configured network tests.

        All destinations are tested concurrently (up to 5 at a time) so that a
        slow destination (e.g. one with traceroute enabled) cannot delay results
        from faster ones.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        logger.info("Running network tests...")

        try:
            destinations = self.fetch_destinations()

            if destinations:
                dns_test_domains = self.fetch_dns_test_domains()

                max_workers = min(len(destinations), 5)
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {
                        executor.submit(
                            self._run_and_send_destination, dest, dns_test_domains
                        ): dest
                        for dest in destinations
                    }
                    for fut in as_completed(futures):
                        dest = futures[fut]
                        try:
                            fut.result()
                        except Exception as exc:
                            logger.error(
                                f"Error testing destination {dest['name']}: {exc}",
                                exc_info=True
                            )
            else:
                logger.warning("No destinations available from server")

        except Exception as e:
            logger.error(f"Error running tests: {e}", exc_info=True)
    
    def start(self):
        """Start the client with scheduled testing"""
        logger.info(f"Starting network monitoring client: {self.client_name}")
        
        # Authenticate with server (obtain or verify API key)
        logger.info("Authenticating with server...")
        if not self.authenticate_with_server():
            logger.error("Authentication failed. Cannot start client without valid API key.")
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
