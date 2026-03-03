"""
Network monitoring client
Runs scheduled tests and sends results to server
"""
import time
import logging
import json
import os
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
                self.client_name = client_config.get('client_name', 'unknown_client')
                self.server_url = server_url or client_config.get('server_url', 'http://localhost:5000')
                self.test_interval = client_config.get('test_interval', 60)
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
        
        self.monitor = NetworkMonitor()
        self.running = False
        self.registered = False
        
        logger.info(f"Client initialized: {self.client_name}")
        logger.info(f"Server URL: {self.server_url}")
        logger.info(f"Test interval: {self.test_interval} seconds")
    
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
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'VaneMonitor-Client/1.0'
                },
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
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
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'VaneMonitor-Client/1.0'
                },
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
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
                headers={'User-Agent': 'VaneMonitor-Client/1.0'}
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
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
                headers={'User-Agent': 'VaneMonitor-Client/1.0'}
            )

            with urllib.request.urlopen(req, timeout=10) as response:
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
