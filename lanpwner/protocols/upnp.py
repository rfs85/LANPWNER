import asyncio
import socket
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
import requests
import struct
import sys

SSDP_ADDR = '239.255.255.250'
SSDP_PORT = 1900
SSDP_MX = 2
SSDP_SEARCH_TARGETS = [
    'ssdp:all',
    'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
    'urn:schemas-upnp-org:service:WANIPConnection:1',
    'urn:schemas-upnp-org:service:WANPPPConnection:1',
    # Media/cast/streaming
    'urn:schemas-upnp-org:device:MediaRenderer:1',
    'urn:schemas-upnp-org:device:MediaServer:1',
    'urn:dial-multiscreen-org:device:dial:1',
    'urn:schemas-wifialliance-org:device:WFDDevice:1',
    'urn:dial-multiscreen-org:service:dial:1',
]

class UPnPModule:
    """
    High-performance UPnP discovery and enumeration using asyncio for concurrency.
    Improved detection: multiple M-SEARCH, NOTIFY listening, interface selection, robust deduplication, vendor fingerprinting, debug output.
    Platform notes:
      - On Windows, interface selection may require admin rights and may not work for all interfaces.
      - netifaces is only required if interface selection is used.
    """
    def __init__(self, timeout: int = 5, max_devices: int = 50, interface: Optional[str] = None, msearch_count: int = 3, listen_extra: int = 2, debug: bool = False):
        self.timeout = timeout
        self.max_devices = max_devices
        self.interface = interface
        self.msearch_count = msearch_count
        self.listen_extra = listen_extra
        self.debug = debug

    def discover(self) -> List[Dict[str, Any]]:
        """
        Discover UPnP devices using SSDP M-SEARCH and NOTIFY listening. Returns a list of device dicts with location and headers.
        """
        loop = asyncio.new_event_loop()
        results = loop.run_until_complete(self._async_discover())
        loop.close()
        return results

    async def _async_discover(self) -> List[Dict[str, Any]]:
        devices = []
        seen_keys = set()
        # Prepare socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)
        # Bind to interface if specified
        if self.interface:
            iface_addr = self._get_iface_addr(self.interface)
            if iface_addr:
                sock.bind((iface_addr, 0))
            else:
                raise RuntimeError("Interface selection requested, but netifaces is not available or interface not found.")
        # Send multiple M-SEARCH requests for each search target
        for st in SSDP_SEARCH_TARGETS:
            msearch = f"M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_ADDR}:{SSDP_PORT}\r\nMAN: \"ssdp:discover\"\r\nMX: {SSDP_MX}\r\nST: {st}\r\n\r\n"
            for _ in range(self.msearch_count):
                sock.sendto(msearch.encode(), (SSDP_ADDR, SSDP_PORT))
                await asyncio.sleep(0.2)
        start = time.time()
        # Listen for responses and NOTIFYs
        while len(devices) < self.max_devices and (time.time() - start) < self.timeout:
            try:
                data, addr = sock.recvfrom(65507)
                resp = data.decode(errors='ignore')
                if self.debug:
                    print(f"[DEBUG] SSDP/NOTIFY from {addr[0]}:\n{resp}\n{'-'*40}")
                headers = self._parse_ssdp_response(resp)
                location = headers.get('location')
                usn = headers.get('usn')
                server = headers.get('server')
                key = (location, usn, server)
                if location and key not in seen_keys:
                    dev = {'location': location, 'headers': headers, 'address': addr[0]}
                    if server:
                        dev['server'] = server
                    devices.append(dev)
                    seen_keys.add(key)
            except socket.timeout:
                break
            except Exception:
                continue
        # Listen for NOTIFY multicast advertisements for extra seconds
        notify_devices = self._listen_notify_multicast(seen_keys, self.listen_extra)
        devices.extend(notify_devices)
        return devices

    def _listen_notify_multicast(self, seen_keys, listen_extra: int) -> List[Dict[str, Any]]:
        """
        Listen for NOTIFY multicast advertisements for listen_extra seconds.
        """
        results = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('', SSDP_PORT))
            mreq = struct.pack('4sl', socket.inet_aton(SSDP_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(listen_extra)
            start = time.time()
            while (time.time() - start) < listen_extra:
                try:
                    data, addr = sock.recvfrom(65507)
                    resp = data.decode(errors='ignore')
                    if resp.startswith('NOTIFY'):
                        if self.debug:
                            print(f"[DEBUG] NOTIFY from {addr[0]}:\n{resp}\n{'-'*40}")
                        headers = self._parse_ssdp_response(resp)
                        location = headers.get('location')
                        usn = headers.get('usn')
                        server = headers.get('server')
                        key = (location, usn, server)
                        if location and key not in seen_keys:
                            dev = {'location': location, 'headers': headers, 'address': addr[0]}
                            if server:
                                dev['server'] = server
                            results.append(dev)
                            seen_keys.add(key)
                except socket.timeout:
                    break
                except Exception:
                    continue
        finally:
            sock.close()
        return results

    def _get_iface_addr(self, iface: str) -> Optional[str]:
        try:
            import netifaces
        except ImportError:
            print("[!] netifaces is required for interface selection. Please install it or omit the --interface option.", file=sys.stderr)
            return None
        try:
            addrs = netifaces.ifaddresses(iface)
            return addrs[netifaces.AF_INET][0]['addr']
        except Exception:
            print(f"[!] Could not get address for interface {iface}", file=sys.stderr)
            return None

    def _parse_ssdp_response(self, response: str) -> Dict[str, str]:
        headers = {}
        for line in response.split('\r\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
        return headers

    def enumerate(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fetch and parse the UPnP device description XML. Returns structured device/service info, including vendor fingerprinting and media/cast detection.
        """
        location = device.get('location')
        try:
            resp = requests.get(location, timeout=self.timeout)
            resp.raise_for_status()
            xml = ET.fromstring(resp.content)
            info = self._parse_device_xml(xml)
            info['location'] = location
            info['address'] = device.get('address')
            # Vendor fingerprinting
            if 'server' in device:
                info['server'] = device['server']
            info['ssdp_headers'] = device.get('headers', {})
            info['vendor'] = self._fingerprint_vendor(info, device)
            # Media/cast/Miracast/Chromecast detection
            info['media_features'] = self._detect_media_features(info, device)
            return info
        except Exception as e:
            return {'location': location, 'error': str(e)}

    def _fingerprint_vendor(self, info: Dict[str, Any], device: Dict[str, Any]) -> str:
        # Try to fingerprint vendor from SSDP headers, device XML, and model/manufacturer
        for key in ['manufacturer', 'modelName', 'modelNumber', 'server']:
            val = info.get(key) or device.get('headers', {}).get(key.lower()) or device.get(key)
            if val:
                return val
        return ''

    def _detect_media_features(self, info: Dict[str, Any], device: Dict[str, Any]) -> list:
        """
        Detect if the device supports casting, Miracast, Chromecast, DLNA, DIAL, MediaRenderer, etc.
        """
        features = []
        # Check deviceType and serviceType
        devtype = (info.get('deviceType') or '').lower()
        services = [svc.get('serviceType','').lower() for svc in info.get('services',[])]
        # SSDP/Server headers
        headers = device.get('headers', {})
        server = headers.get('server','').lower()
        # Common patterns
        if 'mediarenderer' in devtype or 'mediarenderer' in server:
            features.append('MediaRenderer')
        if 'mediaserver' in devtype or 'mediaserver' in server:
            features.append('MediaServer')
        if 'dlna' in devtype or 'dlna' in server:
            features.append('DLNA')
        if 'dial' in devtype or any('dial' in s for s in services):
            features.append('DIAL (Google Cast/Smart TV)')
        if 'wfddevice' in devtype or 'miracast' in devtype or 'wfd' in server:
            features.append('Miracast/Wi-Fi Direct')
        if 'chromecast' in server or 'google inc.' in server or 'chromecast' in devtype:
            features.append('Chromecast')
        # Vendor/brand patterns
        for brand in ['samsung', 'lg', 'sony', 'philips', 'panasonic', 'roku', 'tcl', 'vizio', 'hisense', 'sharp', 'toshiba', 'apple', 'airplay']:
            if brand in server or brand in devtype:
                features.append(f'Brand: {brand.title()}')
        # Service types
        for s in services:
            if 'avtransport' in s:
                features.append('AVTransport (DLNA/UPnP AV)')
        return list(set(features))

    def _parse_device_xml(self, xml: ET.Element) -> Dict[str, Any]:
        ns = {'upnp': 'urn:schemas-upnp-org:device-1-0'}
        device = xml.find('.//device')
        if device is None:
            return {}
        info = {
            'deviceType': device.findtext('deviceType'),
            'friendlyName': device.findtext('friendlyName'),
            'manufacturer': device.findtext('manufacturer'),
            'modelName': device.findtext('modelName'),
            'modelNumber': device.findtext('modelNumber'),
            'serialNumber': device.findtext('serialNumber'),
            'services': []
        }
        service_list = device.find('serviceList')
        if service_list is not None:
            for svc in service_list.findall('service'):
                info['services'].append({
                    'serviceType': svc.findtext('serviceType'),
                    'serviceId': svc.findtext('serviceId'),
                    'controlURL': svc.findtext('controlURL'),
                    'eventSubURL': svc.findtext('eventSubURL'),
                    'SCPDURL': svc.findtext('SCPDURL')
                })
        return info

    def check_misconfigurations(self, device_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for common UPnP misconfigurations and known issues. Returns a list of findings.
        """
        findings = []
        # 1. WANIPConnection service (often vulnerable)
        for svc in device_info.get('services', []):
            if 'WANIPConnection' in (svc.get('serviceType') or ''):
                findings.append({
                    'title': 'WANIPConnection Service Exposed',
                    'description': 'Device exposes WANIPConnection service, which is often vulnerable to remote attacks.',
                    'severity': 'High',
                    'protocol': 'UPnP',
                    'device': device_info.get('friendlyName'),
                    'remediation': 'Restrict access to UPnP services to trusted networks. Disable WAN-side UPnP if not needed.',
                    'cve': ['CVE-2013-0229', 'CVE-2012-5958'],
                    'standards': ['UPnP IGD', 'RFC 6970'],
                    'references': [
                        'https://nvd.nist.gov/vuln/detail/CVE-2013-0229',
                        'https://nvd.nist.gov/vuln/detail/CVE-2012-5958',
                        'https://www.kb.cert.org/vuls/id/357851/'
                    ]
                })
        # 2. Open/unauthenticated control URLs
        for svc in device_info.get('services', []):
            control_url = svc.get('controlURL')
            if control_url and (control_url.startswith('http://') or control_url.startswith('https://')):
                findings.append({
                    'title': 'Open Control URL',
                    'description': f'UPnP service exposes a control URL ({control_url}) that may be accessible without authentication.',
                    'severity': 'Medium',
                    'protocol': 'UPnP',
                    'device': device_info.get('friendlyName'),
                    'remediation': 'Restrict access to control URLs. Require authentication where possible.',
                    'cve': [],
                    'standards': ['UPnP Device Architecture 1.0'],
                    'references': [
                        'https://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf'
                    ]
                })
        # 3. Default credentials exposure (common in some devices)
        if device_info.get('manufacturer', '').lower() in ['d-link', 'netgear', 'linksys', 'belkin']:
            findings.append({
                'title': 'Potential Default Credentials',
                'description': 'Device manufacturer is known to ship with default credentials. Check for unchanged admin passwords.',
                'severity': 'Medium',
                'protocol': 'UPnP',
                'device': device_info.get('friendlyName'),
                'remediation': 'Change default credentials and disable UPnP admin interfaces if not needed.',
                'cve': ['CVE-2014-100005'],
                'standards': ['NIST SP 800-41'],
                'references': [
                    'https://nvd.nist.gov/vuln/detail/CVE-2014-100005',
                    'https://nvd.nist.gov/vuln/detail/CVE-2013-2678'
                ]
            })
        # 4. Known vulnerable device types/models
        vulnerable_models = [
            ('D-Link', 'DIR-615'),
            ('Netgear', 'WNDR3700'),
            ('Linksys', 'WRT54G'),
        ]
        for vendor, model in vulnerable_models:
            if vendor.lower() in (device_info.get('manufacturer', '').lower()) and model.lower() in (device_info.get('modelName', '').lower()):
                findings.append({
                    'title': f'Known Vulnerable Device: {vendor} {model}',
                    'description': f'This device model ({vendor} {model}) is known to have multiple UPnP vulnerabilities.',
                    'severity': 'High',
                    'protocol': 'UPnP',
                    'device': device_info.get('friendlyName'),
                    'remediation': 'Update firmware to the latest version. Disable UPnP if not required.',
                    'cve': ['CVE-2013-0229', 'CVE-2012-5958'],
                    'standards': ['UPnP IGD'],
                    'references': [
                        'https://www.kb.cert.org/vuls/id/357851/',
                        'https://nvd.nist.gov/vuln/detail/CVE-2013-0229'
                    ]
                })
        # 5. Insecure event subscription (eventSubURL)
        for svc in device_info.get('services', []):
            event_url = svc.get('eventSubURL')
            if event_url and (event_url.startswith('http://') or event_url.startswith('https://')):
                findings.append({
                    'title': 'Insecure Event Subscription URL',
                    'description': f'UPnP service exposes an event subscription URL ({event_url}) that may be accessible without authentication.',
                    'severity': 'Low',
                    'protocol': 'UPnP',
                    'device': device_info.get('friendlyName'),
                    'remediation': 'Restrict access to event subscription URLs. Require authentication where possible.',
                    'cve': [],
                    'standards': ['UPnP Device Architecture 1.0'],
                    'references': [
                        'https://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf'
                    ]
                })
        # 6. Exposure of WAN-side services (heuristic: deviceType contains WAN or IGD)
        if device_info.get('deviceType') and any(x in device_info['deviceType'] for x in ['WAN', 'IGD']):
            findings.append({
                'title': 'WAN-side UPnP Service Exposure',
                'description': 'Device appears to expose UPnP services on the WAN interface, which is a major security risk.',
                'severity': 'Critical',
                'protocol': 'UPnP',
                'device': device_info.get('friendlyName'),
                'remediation': 'Disable UPnP on WAN interfaces. Restrict UPnP to trusted LAN segments only.',
                'cve': ['CVE-2013-0229'],
                'standards': ['UPnP IGD', 'NIST SP 800-41'],
                'references': [
                    'https://www.kb.cert.org/vuls/id/357851/',
                    'https://nvd.nist.gov/vuln/detail/CVE-2013-0229'
                ]
            })
        return findings 