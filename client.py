"""
Network monitoring client
Runs scheduled tests and sends results to server
"""
import time
import logging
import json
import os
from pathlib import Path
import ssl
import getpass
import urllib.request
import urllib.error
from typing import Optional
from shared.config import Config
from shared.monitor.network_tests import NetworkMonitor

logger = logging.getLogger(__name__)


class NetworkClient:
    """Client that performs network tests and reports to server"""
    
    def __init__(self, config_file: Optional[str] = None, server_url: Optional[str] = None):
        """Initialize the network client"""

        app_dir = Path(__file__).resolve().parent
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
        
        self.monitor = NetworkMonitor()
        self.running = False
        self.registered = False
        self.ssl_context = self._build_ssl_context()
        
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
                config_data['api_key'] = self.api_key
                config_data.pop('client_username', None)
                config_data.pop('client_password', None)
            else:
                client_section = config_data.setdefault('client', {})
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
        print("\nEnter a server user with role 'client' (or 'admin').\n")

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
    
    def send_results(self, results: list) -> bool:
        """Send test results to server"""
        try:
            data = {
                'client_id': self.client_name,  # Server still uses 'client_id' field
                'results': results
            }
            
            json_data = json.dumps(data).encode('utf-8')
            
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
                timeout=10
            )
            if status == 200:
                logger.info(f"Successfully sent {len(results)} test results to server")
                return True

            logger.error(f"Server responded with status: {status}")
            return False
                    
        except urllib.error.HTTPError as e:
            logger.error(f"Server rejected result submission: {e}")
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
            status, response_body = self._perform_authenticated_request(
                lambda: urllib.request.Request(
                    f"{self.server_url}/api/destinations",
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
                        self.send_results(dest_results)
                    else:
                        logger.warning(f"No results for destination {dest['name']}")
            else:
                logger.warning("No destinations available from server")
            
        except Exception as e:
            logger.error(f"Error running tests: {e}", exc_info=True)
    
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
