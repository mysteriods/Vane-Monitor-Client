"""
ASN lookup and enrichment for path integrity analysis.
"""
import json
import logging
import os
import re
import socket
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ASNLookup:
    """ASN lookup with local caching and WHOIS fallback."""

    ASN_CACHE_FILE = 'asn_cache.json'
    COMMON_TRUSTED_ASNS = {
        '174': 'Cogent Communications',
        '209': 'Qwest (CenturyLink)',
        '1239': 'Sprint',
        '3356': 'Level 3',
        '3549': 'Level 3',
        '6453': 'Tata Communications',
        '6461': 'Zayo',
        '12389': 'Rostelecom',
        '15169': 'Google',
        '16509': 'Amazon AWS',
        '16591': 'Google Fiber',
        '20940': 'Akamai',
        '22927': 'Vodafone',
        '25577': 'Microsoft',
        '32934': 'Meta (Facebook)',
        '39798': 'Yandex',
        '45839': 'Yandex',
        '64512': 'Private (documentation)',
        '65000': 'Private (documentation)',
        '65535': 'Documentation',
    }

    def __init__(self, use_whois: bool = False):
        self.cache = {}
        self.use_whois = use_whois
        self.trusted_asns = set(self.COMMON_TRUSTED_ASNS.keys())
        self.load_cache()

    def load_cache(self):
        if os.path.exists(self.ASN_CACHE_FILE):
            try:
                with open(self.ASN_CACHE_FILE, 'r') as f:
                    self.cache = json.load(f)
                logger.info('Loaded ASN cache with %s entries', len(self.cache))
            except Exception as exc:
                logger.warning('Could not load ASN cache: %s', exc)
                self.cache = {}

    def save_cache(self):
        try:
            with open(self.ASN_CACHE_FILE, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as exc:
            logger.warning('Could not save ASN cache: %s', exc)

    def lookup(self, ip: str) -> Optional[Dict]:
        if not ip or ip == '*':
            return None

        try:
            import ipaddress

            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {
                    'ip': ip,
                    'asn': 'PRIVATE',
                    'name': 'Private network',
                    'is_trusted': True,
                    'is_private': True,
                }
        except ValueError:
            return None

        if ip in self.cache:
            return self.cache[ip]

        result = None
        if self.use_whois:
            result = self._whois_lookup(ip)

        if result:
            result['is_trusted'] = result.get('asn') in self.trusted_asns
            result['is_private'] = False
            self.cache[ip] = result
            self.save_cache()
            return result

        unknown = {
            'ip': ip,
            'asn': 'UNKNOWN',
            'name': 'Unknown ASN',
            'is_trusted': False,
            'is_private': False,
            'source': 'no_lookup',
        }
        self.cache[ip] = unknown
        return unknown

    def _whois_lookup(self, ip: str) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('whois.radb.net', 43))
            sock.send(f'-r AS_SET_MEMBERS {ip}\r\n'.encode())

            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            sock.close()

            decoded = response.decode('utf-8', errors='ignore')
            asn_match = re.search(r'origin:\s+(AS\d+)', decoded)
            if asn_match:
                asn = asn_match.group(1).replace('AS', '')
                name_match = re.search(r'descr:\s+([^\n]+)', decoded)
                name = name_match.group(1).strip() if name_match else f'AS{asn}'
                return {
                    'ip': ip,
                    'asn': asn,
                    'name': name,
                    'source': 'whois',
                }
        except Exception as exc:
            logger.debug('WHOIS lookup failed for %s: %s', ip, exc)

        return None

    def add_trusted_asn(self, asn: str, name: str = None):
        self.trusted_asns.add(asn)
        if name:
            self.COMMON_TRUSTED_ASNS[asn] = name

    def enrich_routers(self, routers: List[str]) -> List[Dict]:
        enriched = []
        for router in routers:
            lookup = self.lookup(router)
            if lookup:
                enriched.append(lookup)
        return enriched

    def detect_unauthorized_asn_changes(self, previous_routers: List[Dict],
                                        current_routers: List[Dict]) -> Dict:
        def normalize_asn(value):
            if value is None:
                return None
            asn = str(value).strip().upper()
            if asn.startswith('AS') and len(asn) > 2:
                asn = asn[2:]
            return asn

        prev_asns = {
            normalize_asn(item.get('asn')): item
            for item in previous_routers
            if normalize_asn(item.get('asn'))
        }
        curr_asns = {
            normalize_asn(item.get('asn')): item
            for item in current_routers
            if normalize_asn(item.get('asn'))
        }

        prev_asn_set = set(prev_asns.keys())
        curr_asn_set = set(curr_asns.keys())
        new_asns = curr_asn_set - prev_asn_set
        removed_asns = prev_asn_set - curr_asn_set

        new_unknown_asns = {asn for asn in new_asns if asn == 'UNKNOWN'}
        new_private_asns = {asn for asn in new_asns if asn == 'PRIVATE'}
        new_trusted_asns = {asn for asn in new_asns if asn in self.trusted_asns}
        new_untrusted_known_asns = new_asns - new_unknown_asns - new_private_asns - new_trusted_asns

        severity = 'none'
        details = []

        if new_untrusted_known_asns:
            severity = 'critical'
            for asn in sorted(new_untrusted_known_asns):
                router_info = curr_asns.get(asn, {})
                details.append(f"NEW UNTRUSTED ASN{asn}: {router_info.get('name', 'Unknown')}")

        if new_unknown_asns:
            if severity != 'critical':
                severity = 'warning'
            details.append('New unresolved ASN detected (lookup returned UNKNOWN)')

        if new_trusted_asns:
            if severity == 'none':
                severity = 'warning'
            for asn in sorted(new_trusted_asns):
                router_info = curr_asns.get(asn, {})
                details.append(f"New trusted ASN{asn}: {router_info.get('name', '')}")

        if new_private_asns:
            details.append('New private-network hop detected')

        if removed_asns:
            details.append(f"Removed {len(removed_asns)} ASN(s): {', '.join(removed_asns)}")

        return {
            'severity': severity,
            'new_asns': sorted(new_asns),
            'new_untrusted_asns': sorted(new_untrusted_known_asns),
            'new_unknown_asns': sorted(new_unknown_asns),
            'removed_asns': sorted(removed_asns),
            'details': details,
            'bgp_hijack_risk': severity == 'critical',
        }