import argparse
import sys
from lanpwner.protocols.upnp import UPnPModule
from lanpwner.protocols.bonjour import BonjourModule
from lanpwner.core.reporting import ReportGenerator
from lanpwner.cli import build_host_inventory, sniff_protocols, dhcp_starvation_attack, dhcp_spoof_attack, dhcp_inform_flood, dhcp_option_overload, dhcp_leasequery, dhcp_decline_flood, dhcp_release_flood, dhcp_relay_spoof, arp_spoof_attack, arp_request_flood, arp_reply_flood, arp_cache_poison, arp_gratuitous, arp_reactive_poison, arp_malformed_flood, arp_scan, arp_storm
from lanpwner.protocols.rtsp import RTSPModule
import requests

LEGAL_DISCLAIMER = """
This tool is for authorized security testing and educational use only.\nUnauthorized use against networks you do not own or have explicit permission to test is illegal and unethical.
"""

def main():
    print(LEGAL_DISCLAIMER)
    parser = argparse.ArgumentParser(description="LANPWNER Main Protocol Management CLI")
    subparsers = parser.add_subparsers(dest='protocol', required=True)

    # UPnP protocol
    upnp_parser = subparsers.add_parser('upnp', help='UPnP/SSDP discovery and enumeration')
    upnp_parser.add_argument('--timeout', type=int, default=5, help='Discovery timeout (seconds)')
    upnp_parser.add_argument('--max-devices', type=int, default=50, help='Maximum devices to enumerate')
    upnp_parser.add_argument('--interface', type=str, help='Network interface to use for discovery')
    upnp_parser.add_argument('--listen-extra', type=int, default=2, help='Extra seconds to listen for NOTIFY/SSDP packets after active scan')
    upnp_parser.add_argument('--report', type=str, help='Save findings to a report file (HTML or JSON)')
    upnp_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    upnp_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # Bonjour/mDNS protocol
    bonjour_parser = subparsers.add_parser('bonjour', help='Bonjour/mDNS (AirPlay, Chromecast) discovery')
    bonjour_parser.add_argument('--timeout', type=int, default=5, help='Discovery timeout (seconds)')
    bonjour_parser.add_argument('--interface', type=str, help='Network interface to use for discovery (optional)')
    bonjour_parser.add_argument('--report', type=str, help='Save findings to a report file (HTML or JSON)')
    bonjour_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    bonjour_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # Sniff protocol
    sniff_parser = subparsers.add_parser('sniff', help='Passive protocol/device detection and auto-enumeration')
    sniff_parser.add_argument('--interface', type=str, required=True, help='Network interface to sniff')
    sniff_parser.add_argument('--timeout', type=int, default=10, help='Sniffing duration (seconds)')
    sniff_parser.add_argument('--report', type=str, help='Save findings to a report file (HTML or JSON)')
    sniff_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    sniff_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # Inventory protocol
    inventory_parser = subparsers.add_parser('inventory', help='Passive DHCP/ARP host inventory')
    inventory_parser.add_argument('--interface', type=str, required=True, help='Network interface to sniff')
    inventory_parser.add_argument('--timeout', type=int, default=30, help='Sniffing duration (seconds)')
    inventory_parser.add_argument('--report', type=str, help='Save inventory to a report file (HTML or JSON)')
    inventory_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    inventory_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # DHCP protocol (all DHCP attacks)
    dhcp_parser = subparsers.add_parser('dhcp', help='DHCP attacks and enumeration (authorized testing only)')
    dhcp_group = dhcp_parser.add_mutually_exclusive_group(required=True)
    dhcp_group.add_argument('--starvation', action='store_true', help='Perform DHCP starvation attack')
    dhcp_group.add_argument('--spoof', action='store_true', help='Run rogue DHCP server (spoof)')
    dhcp_group.add_argument('--inform-flood', action='store_true', help='Flood network with DHCP INFORM packets')
    dhcp_group.add_argument('--option-overload', action='store_true', help='Send DHCP packets with excessive/malformed options')
    dhcp_group.add_argument('--leasequery', action='store_true', help='Send DHCPLEASEQUERY packets to enumerate leases')
    dhcp_group.add_argument('--decline-flood', action='store_true', help='Flood server with DECLINE messages')
    dhcp_group.add_argument('--release-flood', action='store_true', help='Flood server with RELEASE messages')
    dhcp_group.add_argument('--relay-spoof', action='store_true', help='Send packets with forged Option 82 (Relay Agent)')
    dhcp_parser.add_argument('--interface', type=str, required=True, help='Network interface to use')
    dhcp_parser.add_argument('--count', type=int, default=100, help='Number of packets (for applicable attacks)')
    dhcp_parser.add_argument('--pool-start', type=str, help='Start of IP pool for DHCP spoofing')
    dhcp_parser.add_argument('--pool-end', type=str, help='End of IP pool for DHCP spoofing')
    dhcp_parser.add_argument('--gateway', type=str, help='Gateway IP to offer in DHCP spoofing')
    dhcp_parser.add_argument('--dns', type=str, help='DNS server IP to offer in DHCP spoofing')
    dhcp_parser.add_argument('--lease-time', type=int, default=3600, help='Lease time for DHCP spoofing')
    dhcp_parser.add_argument('--report', type=str, help='Save findings to a report file (HTML or JSON)')
    dhcp_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    dhcp_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # ARP protocol (ARP attacks)
    arp_parser = subparsers.add_parser('arp', help='ARP attacks (authorized testing only)')
    arp_group = arp_parser.add_mutually_exclusive_group(required=True)
    arp_group.add_argument('--spoof', action='store_true', help='Perform ARP spoofing attack')
    arp_group.add_argument('--request-flood', action='store_true', help='Flood the network with ARP requests')
    arp_group.add_argument('--reply-flood', action='store_true', help='Flood the network with ARP replies to random IPs')
    arp_group.add_argument('--cache-poison', action='store_true', help='Send targeted ARP cache poisoning packets')
    arp_group.add_argument('--gratuitous', action='store_true', help='Send gratuitous ARP packets (ARP probe)')
    arp_group.add_argument('--reactive-poison', action='store_true', help='Listen for ARP requests and poison on demand')
    arp_group.add_argument('--malformed-flood', action='store_true', help='Send malformed ARP packets')
    arp_group.add_argument('--scan', action='store_true', help='Perform ARP scan of a subnet')
    arp_group.add_argument('--storm', action='store_true', help='Send a mixed ARP storm (requests/replies)')
    arp_parser.add_argument('--interface', type=str, required=True, help='Network interface to use')
    arp_parser.add_argument('--target-ip', type=str, help='Target IP for spoofing/poisoning')
    arp_parser.add_argument('--spoof-ip', type=str, help='IP to spoof for ARP spoofing/poisoning')
    arp_parser.add_argument('--spoof-mac', type=str, default='de:ad:be:ef:00:01', help='MAC to use for spoofing/poisoning')
    arp_parser.add_argument('--count', type=int, default=10, help='Number of packets to send (where applicable)')
    arp_parser.add_argument('--subnet', type=str, default='192.168.1.0/24', help='Subnet for ARP scan')
    arp_parser.add_argument('--duration', type=int, default=30, help='Duration for reactive poisoning (seconds)')
    arp_parser.add_argument('--report', type=str, help='Save findings to a report file (HTML or JSON)')
    arp_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    arp_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # RTSP protocol (auditing/attacks)
    rtsp_parser = subparsers.add_parser('rtsp', help='RTSP auditing and attacks')
    rtsp_group = rtsp_parser.add_mutually_exclusive_group(required=True)
    rtsp_group.add_argument('--discover', action='store_true', help='Discover RTSP endpoints on the LAN')
    rtsp_group.add_argument('--enumerate', action='store_true', help='Enumerate RTSP endpoint details')
    rtsp_group.add_argument('--audit', action='store_true', help='Audit for weak/default credentials and auth bypass')
    rtsp_group.add_argument('--options-fingerprint', action='store_true', help='Fingerprint RTSP features via OPTIONS')
    rtsp_group.add_argument('--describe-leak', action='store_true', help='Attempt unauthenticated DESCRIBE to leak info')
    rtsp_group.add_argument('--teardown-dos', action='store_true', help='Attempt DoS via repeated TEARDOWN requests')
    rtsp_parser.add_argument('--endpoint', type=str, help='RTSP endpoint (rtsp://...)')
    rtsp_parser.add_argument('--username', type=str, help='Username for RTSP authentication')
    rtsp_parser.add_argument('--password', type=str, help='Password for RTSP authentication')
    rtsp_parser.add_argument('--timeout', type=int, default=10, help='Discovery timeout in seconds (for --discover)')
    rtsp_parser.add_argument('--report', type=str, help='Save findings to a report file (HTML or JSON)')
    rtsp_parser.add_argument('--format', type=str, choices=['html', 'json'], default='html', help='Report format')
    rtsp_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # Cast protocol (casting attacks)
    cast_parser = subparsers.add_parser('cast', help='Casting session detection and attacks')
    cast_group = cast_parser.add_mutually_exclusive_group(required=True)
    cast_group.add_argument('--detect-sessions', action='store_true', help='Detect ongoing casting sessions on the LAN')
    cast_group.add_argument('--hijack', action='store_true', help='Hijack a detected casting session')
    cast_group.add_argument('--broadcast', action='store_true', help='Broadcast a video to all TVs/media servers')
    cast_parser.add_argument('--video-url', type=str, help='Video URL to cast/hijack (YouTube, direct media, etc.)')
    cast_parser.add_argument('--target', type=str, help='Target device name or address (for hijack)')
    cast_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()

    if args.protocol == 'upnp':
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
            report.generate(format=args.format, save_path=args.report)
            print(f'[*] Report saved to {args.report}')

    elif args.protocol == 'bonjour':
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
            report.generate(format=args.format, save_path=args.report)
            print(f'[*] Report saved to {args.report}')

    elif args.protocol == 'sniff':
        detected = sniff_protocols(args.interface, timeout=args.timeout, debug=args.debug)
        report = ReportGenerator()
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
        for dev in sniff_protocols.detected_devices:
            report.add_discovery(dev)
        if args.report:
            report.generate(format=args.format, save_path=args.report)
            print(f'[*] Report saved to {args.report}')

    elif args.protocol == 'inventory':
        inventory = build_host_inventory(args.interface, timeout=args.timeout, debug=args.debug)
        report = ReportGenerator()
        for host in inventory:
            report.add_discovery(host)
        if args.report:
            report.generate(format=args.format, save_path=args.report)
            print(f'[*] Report saved to {args.report}')

    elif args.protocol == 'dhcp':
        if args.starvation:
            dhcp_starvation_attack(args.interface, count=args.count, debug=args.debug)
        elif args.spoof:
            if not (args.pool_start and args.pool_end and args.gateway and args.dns):
                print('[!] --pool-start, --pool-end, --gateway, and --dns are required for DHCP spoof.')
                sys.exit(1)
            dhcp_spoof_attack(args.interface, pool_start=args.pool_start, pool_end=args.pool_end, gateway=args.gateway, dns=args.dns, lease_time=args.lease_time, debug=args.debug)
        elif args.inform_flood:
            dhcp_inform_flood(args.interface, count=args.count, debug=args.debug)
        elif args.option_overload:
            dhcp_option_overload(args.interface, count=args.count, debug=args.debug)
        elif args.leasequery:
            dhcp_leasequery(args.interface, debug=args.debug)
        elif args.decline_flood:
            dhcp_decline_flood(args.interface, count=args.count, debug=args.debug)
        elif args.release_flood:
            dhcp_release_flood(args.interface, count=args.count, debug=args.debug)
        elif args.relay_spoof:
            dhcp_relay_spoof(args.interface, count=args.count, debug=args.debug)
        else:
            print('[!] No DHCP attack selected.')
            sys.exit(1)

    elif args.protocol == 'arp':
        if args.spoof:
            if not args.target_ip or not args.spoof_ip:
                print('[!] --target-ip and --spoof-ip are required for ARP spoofing.')
                sys.exit(1)
            arp_spoof_attack(args.interface, target_ip=args.target_ip, spoof_ip=args.spoof_ip, count=args.count, debug=args.debug)
        elif args.request_flood:
            arp_request_flood(args.interface, count=args.count, debug=args.debug)
        elif args.reply_flood:
            arp_reply_flood(args.interface, count=args.count, debug=args.debug)
        elif args.cache_poison:
            if not args.target_ip or not args.spoof_ip:
                print('[!] --target-ip and --spoof-ip are required for ARP cache poisoning.')
                sys.exit(1)
            arp_cache_poison(args.interface, target_ip=args.target_ip, spoof_ip=args.spoof_ip, spoof_mac=args.spoof_mac, count=args.count, debug=args.debug)
        elif args.gratuitous:
            if not args.spoof_ip:
                print('[!] --spoof-ip is required for gratuitous ARP.')
                sys.exit(1)
            arp_gratuitous(args.interface, spoof_ip=args.spoof_ip, spoof_mac=args.spoof_mac, count=args.count, debug=args.debug)
        elif args.reactive_poison:
            if not args.spoof_ip:
                print('[!] --spoof-ip is required for reactive ARP poisoning.')
                sys.exit(1)
            arp_reactive_poison(args.interface, target_ip=args.target_ip, spoof_ip=args.spoof_ip, spoof_mac=args.spoof_mac, debug=args.debug, duration=args.duration)
        elif args.malformed_flood:
            arp_malformed_flood(args.interface, count=args.count, debug=args.debug)
        elif args.scan:
            arp_scan(args.interface, subnet=args.subnet, debug=args.debug)
        elif args.storm:
            arp_storm(args.interface, count=args.count, debug=args.debug)
        else:
            print('[!] No ARP attack selected.')
            sys.exit(1)

    elif args.protocol == 'rtsp':
        rtsp = RTSPModule()
        if args.discover:
            print(f'[*] Discovering RTSP endpoints (timeout: {args.timeout}s)...')
            endpoints = rtsp.discover(timeout=args.timeout)
            print(f'[*] Found {len(endpoints) if endpoints else 0} RTSP endpoint(s).')
            if endpoints:
                for ep in endpoints:
                    print(f'    - {ep}')
        elif args.enumerate:
            if not args.endpoint:
                print('[!] --endpoint is required for enumeration.')
                sys.exit(1)
            info = rtsp.enumerate(args.endpoint)
            print(f'[*] Enumeration result for {args.endpoint}:')
            print(info)
        elif args.audit:
            if not args.endpoint:
                print('[!] --endpoint is required for audit.')
                sys.exit(1)
            result = rtsp.audit(args.endpoint, username=args.username, password=args.password)
            print(f'[*] Audit result for {args.endpoint}:')
            print(result)
        elif args.options_fingerprint:
            if not args.endpoint:
                print('[!] --endpoint is required for OPTIONS fingerprinting.')
                sys.exit(1)
            result = rtsp.options_fingerprint(args.endpoint)
            print(f'[*] OPTIONS fingerprint for {args.endpoint}:')
            print(result)
        elif args.describe_leak:
            if not args.endpoint:
                print('[!] --endpoint is required for DESCRIBE leak test.')
                sys.exit(1)
            result = rtsp.describe_leak(args.endpoint)
            print(f'[*] DESCRIBE leak result for {args.endpoint}:')
            print(result)
        elif args.teardown_dos:
            if not args.endpoint:
                print('[!] --endpoint is required for TEARDOWN DoS.')
                sys.exit(1)
            result = rtsp.teardown_dos(args.endpoint)
            print(f'[*] TEARDOWN DoS result for {args.endpoint}:')
            print(result)
        else:
            print('[!] No RTSP action selected.')
            sys.exit(1)

    elif args.protocol == 'cast':
        # 1. Detect all castable devices (Bonjour/mDNS and UPnP)
        bonjour = BonjourModule(timeout=5)
        upnp = UPnPModule(timeout=5, debug=args.debug)
        devices = []
        mobile_devices = []
        if args.detect_sessions or args.hijack or args.broadcast:
            print('[*] Enumerating Bonjour/mDNS (Chromecast, AirPlay, Mobile) devices...')
            bonjour_services = bonjour.discover()
            for svc in bonjour_services:
                # Mobile device detection via Bonjour
                name = svc.get('name','').lower()
                props = svc.get('properties', {})
                is_mobile = False
                if 'iphone' in name or 'ipad' in name or 'android' in name or 'ios' in name:
                    is_mobile = True
                if 'model' in props and ('iphone' in props['model'].lower() or 'ipad' in props['model'].lower() or 'android' in props['model'].lower()):
                    is_mobile = True
                if is_mobile:
                    mobile_devices.append({'type': 'bonjour', 'info': svc})
                if svc.get('service_type') in ['_googlecast._tcp.local.', '_chromecast._tcp.local.', '_airplay._tcp.local.']:
                    devices.append({'type': 'bonjour', 'info': svc})
            print(f'[*] Enumerating UPnP/SSDP (DLNA, MediaRenderer, Smart TV, Mobile) devices...')
            upnp_devices = upnp.discover()
            for dev in upnp_devices:
                info = upnp.enumerate(dev)
                features = info.get('media_features', [])
                # Mobile device detection via UPnP
                vendor = (info.get('manufacturer') or '').lower()
                model = (info.get('modelName') or '').lower()
                if any(x in vendor for x in ['samsung', 'apple', 'huawei', 'xiaomi', 'oneplus', 'google', 'android', 'iphone', 'ipad']) or any(x in model for x in ['android', 'iphone', 'ipad']):
                    mobile_devices.append({'type': 'upnp', 'info': info})
                if any(f in features for f in ['MediaRenderer', 'DLNA', 'Chromecast', 'DIAL (Google Cast/Smart TV)', 'AVTransport (DLNA/UPnP AV)']):
                    devices.append({'type': 'upnp', 'info': info})
        if args.detect_sessions:
            print(f'[*] Detected {len(devices)} cast-capable device(s):')
            for d in devices:
                session_state = None
                if d['type'] == 'bonjour':
                    name = d['info'].get('name')
                    addresses = d['info'].get('addresses')
                    ip = addresses[0] if addresses else None
                    print(f'    - Bonjour: {name} ({addresses})')
                    # Chromecast/Google Cast session detection
                    if '_googlecast._tcp.local.' in d['info'].get('service_type','') or '_chromecast._tcp.local.' in d['info'].get('service_type',''):
                        if ip:
                            try:
                                # Query /setup/eureka_info for status
                                resp = requests.get(f'http://{ip}:8008/setup/eureka_info', timeout=2)
                                if resp.ok:
                                    data = resp.json()
                                    app = data.get('running', None)
                                    if app:
                                        session_state = f'App running: {app}'
                                    else:
                                        session_state = 'Idle/No app running'
                                # Query /apps for current app
                                resp2 = requests.get(f'http://{ip}:8008/apps', timeout=2)
                                if resp2.ok and 'YouTube' in resp2.text:
                                    session_state = 'YouTube app active'
                            except Exception as e:
                                if args.debug:
                                    print(f'[DEBUG] Chromecast session query failed: {e}')
                    elif '_airplay._tcp.local.' in d['info'].get('service_type',''):
                        # AirPlay: no public API for session, but can check if port 7000 is open
                        if ip:
                            import socket
                            s = socket.socket()
                            s.settimeout(1)
                            try:
                                s.connect((ip, 7000))
                                session_state = 'AirPlay service reachable (port 7000 open)'
                                s.close()
                            except Exception:
                                session_state = 'AirPlay service not reachable'
                    if session_state:
                        print(f'        [Session] {session_state}')
                elif d['type'] == 'upnp':
                    name = d['info'].get('friendlyName')
                    address = d['info'].get('address')
                    features = d['info'].get('media_features', [])
                    print(f'    - UPnP: {name} ({address}) [{", ".join(features)}]')
                    # DLNA/UPnP AVTransport session detection
                    avtransport_url = None
                    for svc in d['info'].get('services', []):
                        if svc.get('serviceType','').lower().endswith('avtransport:1'):
                            avtransport_url = svc.get('controlURL')
                            break
                    if avtransport_url and address:
                        # Try to send GetTransportInfo SOAP request
                        try:
                            soap_body = '''<?xml version="1.0" encoding="utf-8"?>
                                <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                                  <s:Body>
                                    <u:GetTransportInfo xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
                                      <InstanceID>0</InstanceID>
                                    </u:GetTransportInfo>
                                  </s:Body>
                                </s:Envelope>'''
                            headers = {
                                'Content-Type': 'text/xml; charset="utf-8"',
                                'SOAPACTION': '"urn:schemas-upnp-org:service:AVTransport:1#GetTransportInfo"'
                            }
                            url = avtransport_url
                            if not url.startswith('http'):
                                url = f'http://{address}{url}'
                            resp = requests.post(url, data=soap_body, headers=headers, timeout=2)
                            if resp.ok and 'CurrentTransportState' in resp.text:
                                if 'PLAYING' in resp.text:
                                    session_state = 'Media playing'
                                elif 'PAUSED' in resp.text:
                                    session_state = 'Media paused'
                                elif 'STOPPED' in resp.text:
                                    session_state = 'Stopped'
                                else:
                                    session_state = 'Unknown state'
                        except Exception as e:
                            if args.debug:
                                print(f'[DEBUG] UPnP AVTransport session query failed: {e}')
                    if session_state:
                        print(f'        [Session] {session_state}')
            if mobile_devices:
                print(f'[*] Detected {len(mobile_devices)} mobile device(s) (Android/iOS):')
                for m in mobile_devices:
                    if m['type'] == 'bonjour':
                        name = m['info'].get('name')
                        addresses = m['info'].get('addresses')
                        print(f'    - Bonjour Mobile: {name} ({addresses})')
                    elif m['type'] == 'upnp':
                        name = m['info'].get('friendlyName')
                        address = m['info'].get('address')
                        print(f'    - UPnP Mobile: {name} ({address})')
                print('[*] (Mobile device takeover is a stub. See below for possible methods.)')
            print('[*] (Session state detection is now protocol-specific. See above for details.)')
        elif args.hijack:
            print('[*] Hijack mode selected.')
            print('[*] (Hijack logic is a stub. Would send cast/play command to the target device.)')
            print(f'    Target: {args.target}, Video: {args.video_url}')
            if mobile_devices:
                print(f'[*] {len(mobile_devices)} mobile device(s) detected. Attempting takeover (stub):')
                for m in mobile_devices:
                    if m['type'] == 'bonjour':
                        name = m['info'].get('name')
                        print(f'    - Would attempt AirPlay/Bonjour takeover: {name}')
                    elif m['type'] == 'upnp':
                        name = m['info'].get('friendlyName')
                        print(f'    - Would attempt UPnP/DIAL takeover: {name}')
                print('[*] (Mobile device takeover logic is a stub. Would attempt to send media/cast command if supported.)')
        elif args.broadcast:
            print('[*] Broadcast mode selected.')
            print(f'[*] Attempting to broadcast {args.video_url} to all detected TVs/media servers...')
            for d in devices:
                if d['type'] == 'bonjour':
                    name = d['info'].get('name')
                    print(f'    - Would cast to Bonjour device: {name}')
                elif d['type'] == 'upnp':
                    name = d['info'].get('friendlyName')
                    print(f'    - Would cast to UPnP device: {name}')
            if mobile_devices:
                print(f'[*] Attempting to broadcast to {len(mobile_devices)} mobile device(s) (stub):')
                for m in mobile_devices:
                    if m['type'] == 'bonjour':
                        name = m['info'].get('name')
                        print(f'    - Would attempt AirPlay/Bonjour broadcast: {name}')
                    elif m['type'] == 'upnp':
                        name = m['info'].get('friendlyName')
                        print(f'    - Would attempt UPnP/DIAL broadcast: {name}')
                print('[*] (Mobile device broadcast logic is a stub. Would attempt to send media/cast command if supported.)')
        else:
            print('[!] No cast action selected.')
            sys.exit(1)

if __name__ == "__main__":
    main()
