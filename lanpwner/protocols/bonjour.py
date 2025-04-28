from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
from typing import List, Dict, Any
import socket

class BonjourModule:
    """
    Enumerate Bonjour/mDNS services, including AirPlay and Chromecast (Google Cast).
    """
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.services = ['_airplay._tcp.local.', '_googlecast._tcp.local.', '_chromecast._tcp.local.']
        self.results: List[Dict[str, Any]] = []

    def discover(self) -> List[Dict[str, Any]]:
        zeroconf = Zeroconf()
        try:
            for service in self.services:
                listener = _BonjourListener(service)
                browser = ServiceBrowser(zeroconf, service, listener)
            import time
            time.sleep(self.timeout)
            self.results = _BonjourListener.collected_results()
        finally:
            zeroconf.close()
        return self.results

    def enumerate(self, service: Dict[str, Any]) -> Dict[str, Any]:
        # For Bonjour, discovery and enumeration are combined
        return service

    def check_misconfigurations(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        # Example: AirPlay with no password
        if service.get('service_type') == '_airplay._tcp.local.':
            txt = service.get('properties', {})
            if 'pw' not in txt or txt.get('pw') == 'false':
                findings.append({
                    'title': 'AirPlay Service Without Password',
                    'description': 'AirPlay service is advertised without password protection.',
                    'severity': 'Medium',
                    'protocol': 'Bonjour/mDNS',
                    'device': service.get('name'),
                    'remediation': 'Enable password protection for AirPlay.',
                    'cve': [],
                    'standards': ['RFC 6762', 'RFC 6763'],
                    'references': [
                        'https://support.apple.com/en-us/HT204380',
                        'https://datatracker.ietf.org/doc/html/rfc6762',
                        'https://datatracker.ietf.org/doc/html/rfc6763'
                    ]
                })
        # Chromecast: check for default names or open access
        if service.get('service_type') in ['_googlecast._tcp.local.', '_chromecast._tcp.local.']:
            if 'default' in service.get('name','').lower():
                findings.append({
                    'title': 'Chromecast With Default Name',
                    'description': 'Chromecast device is using a default name, which may indicate default configuration.',
                    'severity': 'Low',
                    'protocol': 'Bonjour/mDNS',
                    'device': service.get('name'),
                    'remediation': 'Change the device name to something unique and review security settings.',
                    'cve': [],
                    'standards': ['RFC 6762', 'RFC 6763'],
                    'references': [
                        'https://support.google.com/chromecast/answer/2998456',
                        'https://datatracker.ietf.org/doc/html/rfc6762',
                        'https://datatracker.ietf.org/doc/html/rfc6763'
                    ]
                })
        return findings

class _BonjourListener(ServiceListener):
    _results = []

    def __init__(self, service_type: str):
        self.service_type = service_type

    @classmethod
    def collected_results(cls) -> List[Dict[str, Any]]:
        return cls._results

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            # Safely handle properties that might be None
            properties = {}
            if info.properties:
                for k, v in info.properties.items():
                    if k is not None and v is not None:
                        try:
                            key = k.decode() if isinstance(k, bytes) else str(k)
                            value = v.decode(errors='ignore') if isinstance(v, bytes) else str(v)
                            properties[key] = value
                        except Exception:
                            continue

            service = {
                'name': name.replace(f'.{type_}', ''),
                'service_type': type_,
                'server': info.server,
                'address': socket.inet_ntoa(info.addresses[0]) if info.addresses else None,
                'port': info.port,
                'properties': properties
            }
            self._results.append(service)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass 