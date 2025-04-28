import argparse
import sys
import importlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None
from lanpwner.protocols.upnp import UPnPModule
from lanpwner.protocols.bonjour import BonjourModule
from lanpwner.protocols.rtsp import RTSPModule
from lanpwner.protocols.cast import CastModule
from lanpwner.core.reporting import ReportGenerator
from lanpwner.cli import build_host_inventory, sniff_protocols, dhcp_starvation_attack, dhcp_spoof_attack, dhcp_inform_flood, dhcp_option_overload, dhcp_leasequery, dhcp_decline_flood, dhcp_release_flood, dhcp_relay_spoof, arp_spoof_attack, arp_request_flood, arp_reply_flood, arp_cache_poison, arp_gratuitous, arp_reactive_poison, arp_malformed_flood, arp_scan, arp_storm

LEGAL_DISCLAIMER = """
This tool is for authorized security testing and educational use only.\nUnauthorized use against networks you do not own or have explicit permission to test is illegal and unethical.
"""

def enumerate_and_report(module, devices, report, check_misconfig=True, debug=False, threads=1, progress_label=None):
    # Multi-threaded enumeration for large device lists, with progress bar and robust error handling
    def enum_one(dev):
        try:
            info = module.enumerate(dev['ip'] if isinstance(dev, dict) and 'ip' in dev else dev)
            return (dev, info)
        except Exception as e:
            return (dev, {'error': str(e)})
    results = []
    bar = None
    total = len(devices)
    if threads > 1 and total > 1:
        if tqdm:
            bar = tqdm(total=total, desc=progress_label or 'Enumerating', unit='dev')
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futs = {executor.submit(enum_one, dev): dev for dev in devices}
            for fut in as_completed(futs):
                dev, info = fut.result()
                results.append((dev, info))
                if bar:
                    bar.update(1)
        if bar:
            bar.close()
    else:
        if tqdm:
            bar = tqdm(total=total, desc=progress_label or 'Enumerating', unit='dev')
        for dev in devices:
            results.append(enum_one(dev))
            if bar:
                bar.update(1)
        if bar:
            bar.close()
    for dev, info in results:
        if 'error' not in info:
            if check_misconfig and hasattr(module, 'check_misconfigurations'):
                findings = module.check_misconfigurations(info)
                for finding in findings:
                    print(f"[!] {finding['title']} on {finding.get('device','')} ({finding.get('severity','')})")
                    print(f"    {finding['description']}")
                for finding in findings:
                    report.add_vulnerability(finding)
            report.add_discovery(info)
        else:
            print(f"[!] Error enumerating {dev.get('ip', dev)}: {info['error']}")

def main():
    print(LEGAL_DISCLAIMER)
    parser = argparse.ArgumentParser(description="LANPWNER Main Protocol Management CLI")
    parser.add_argument('--debug', action='store_true', help='Enable debug output (global)')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads for batch/protocol scans (default: 4)')
    parser.add_argument('--modbus-threads', type=int, help='Threads for Modbus enumeration')
    parser.add_argument('--snmp-threads', type=int, help='Threads for SNMP enumeration')
    parser.add_argument('--bacnet-threads', type=int, help='Threads for BACnet enumeration')
    parser.add_argument('--sip-threads', type=int, help='Threads for SIP enumeration')
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
    cast_parser.add_argument('--airplay-message', type=str, help='Message to inject via AirPlay (text/photo/alert)')
    cast_parser.add_argument('--airplay-message-type', type=str, choices=['text', 'photo', 'alert'], default='text', help='Type of AirPlay message to inject')
    cast_parser.add_argument('--airplay-tts', action='store_true', help='Inject AirPlay TTS (text-to-speech) audio')
    cast_parser.add_argument('--airplay-bruteforce-pin', action='store_true', help='Brute-force AirPlay PIN (0000-9999)')
    cast_parser.add_argument('--mqtt-topic', type=str, help='MQTT topic to publish/subscribe')
    cast_parser.add_argument('--mqtt-message', type=str, help='MQTT message to publish')
    cast_parser.add_argument('--mqtt-action', type=str, choices=['publish', 'subscribe'], help='MQTT action')
    cast_parser.add_argument('--mqtt-userlist', type=str, help='File with MQTT usernames (one per line)')
    cast_parser.add_argument('--mqtt-passlist', type=str, help='File with MQTT passwords (one per line)')
    cast_parser.add_argument('--mqtt-retained', action='store_true', help='Publish MQTT message as retained')

    # Modbus protocol
    modbus_parser = subparsers.add_parser('modbus', help='Modbus/TCP discovery, enumeration, and attacks')
    modbus_group = modbus_parser.add_mutually_exclusive_group(required=True)
    modbus_group.add_argument('--discover', action='store_true', help='Discover Modbus devices')
    modbus_group.add_argument('--enumerate', action='store_true', help='Enumerate Modbus device info')
    modbus_group.add_argument('--write-single-coil', action='store_true', help='Write single coil (dangerous!)')
    modbus_group.add_argument('--write-single-register', action='store_true', help='Write single register (dangerous!)')
    modbus_group.add_argument('--write-multiple-coils', action='store_true', help='Write multiple coils (dangerous!)')
    modbus_group.add_argument('--write-multiple-registers', action='store_true', help='Write multiple registers (dangerous!)')
    modbus_group.add_argument('--shell', action='store_true', help='Simulate shell execution via register write (dangerous!)')
    modbus_parser.add_argument('--ip', type=str, help='Target IP for enumeration/attack')
    modbus_parser.add_argument('--address', type=int, help='Coil/Register address')
    modbus_parser.add_argument('--value', type=int, help='Value to write (for single register/shell)')
    modbus_parser.add_argument('--values', type=str, help='Comma-separated values for multiple writes')
    modbus_parser.add_argument('--subnet', type=str, default='192.168.1.0/24', help='Subnet for discovery')
    modbus_parser.add_argument('--yes-i-am-authorized', action='store_true', help='Confirm you are authorized to run attacks')
    modbus_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # BACnet protocol
    bacnet_parser = subparsers.add_parser('bacnet', help='BACnet discovery and enumeration')
    bacnet_group = bacnet_parser.add_mutually_exclusive_group(required=True)
    bacnet_group.add_argument('--discover', action='store_true', help='Discover BACnet devices')
    bacnet_group.add_argument('--enumerate', action='store_true', help='Enumerate BACnet device info')
    bacnet_parser.add_argument('--ip', type=str, help='Target IP for enumeration')
    bacnet_parser.add_argument('--subnet', type=str, default='192.168.1.0/24', help='Subnet for discovery')
    bacnet_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # SNMP protocol
    snmp_parser = subparsers.add_parser('snmp', help='SNMP discovery, enumeration, and brute-force')
    snmp_group = snmp_parser.add_mutually_exclusive_group(required=True)
    snmp_group.add_argument('--discover', action='store_true', help='Discover SNMP devices')
    snmp_group.add_argument('--enumerate', action='store_true', help='Enumerate SNMP device info')
    snmp_group.add_argument('--brute-force', action='store_true', help='Brute-force SNMP community strings')
    snmp_parser.add_argument('--ip', type=str, help='Target IP for enumeration/attack')
    snmp_parser.add_argument('--community', type=str, default='public', help='SNMP community string')
    snmp_parser.add_argument('--subnet', type=str, default='192.168.1.0/24', help='Subnet for discovery')
    snmp_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # SIP protocol
    sip_parser = subparsers.add_parser('sip', help='SIP discovery, user enumeration, brute-force, and spoofing')
    sip_group = sip_parser.add_mutually_exclusive_group(required=True)
    sip_group.add_argument('--discover', action='store_true', help='Discover SIP devices')
    sip_group.add_argument('--enumerate-users', action='store_true', help='Enumerate SIP users/extensions')
    sip_group.add_argument('--brute-force', action='store_true', help='Brute-force SIP REGISTER for a user')
    sip_group.add_argument('--spoof-call', action='store_true', help='Send a spoofed SIP INVITE')
    sip_parser.add_argument('--ip', type=str, help='Target IP for enumeration/attack')
    sip_parser.add_argument('--user', type=str, help='SIP user/extension')
    sip_parser.add_argument('--passlist', type=str, help='File with passwords for brute-force')
    sip_parser.add_argument('--from-user', type=str, help='From user for spoofing')
    sip_parser.add_argument('--to-user', type=str, help='To user for spoofing')
    sip_parser.add_argument('--subnet', type=str, default='192.168.1.0/24', help='Subnet for discovery')
    sip_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # Batch scan mode
    scan_parser = subparsers.add_parser('scan', help='Scan all supported protocols (discovery/enumeration)')
    scan_parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()
    global_debug = getattr(args, 'debug', False)
    threads = getattr(args, 'threads', 4)
    modbus_threads = getattr(args, 'modbus_threads', None) or threads
    snmp_threads = getattr(args, 'snmp_threads', None) or threads
    bacnet_threads = getattr(args, 'bacnet_threads', None) or threads
    sip_threads = getattr(args, 'sip_threads', None) or threads

    try:
        if args.protocol == 'upnp':
            upnp = UPnPModule(timeout=args.timeout, max_devices=args.max_devices, interface=args.interface, listen_extra=args.listen_extra, debug=args.debug or global_debug)
            print('[*] Discovering UPnP devices...')
            devices = upnp.discover()
            print(f'[*] Found {len(devices)} device(s). Enumerating...')
            report = ReportGenerator()
            enumerate_and_report(upnp, devices, report, debug=args.debug or global_debug, threads=threads, progress_label='UPnP')
            if args.report:
                report.generate(format=args.format, save_path=args.report)
                print(f'[*] Report saved to {args.report}')

        elif args.protocol == 'bonjour':
            bonjour = BonjourModule(timeout=args.timeout)
            print('[*] Discovering Bonjour/mDNS (AirPlay, Chromecast) devices...')
            services = bonjour.discover()
            print(f'[*] Found {len(services)} service(s).')
            report = ReportGenerator()
            enumerate_and_report(bonjour, services, report, check_misconfig=False, debug=args.debug or global_debug, threads=threads, progress_label='Bonjour')
            if args.report:
                report.generate(format=args.format, save_path=args.report)
                print(f'[*] Report saved to {args.report}')

        elif args.protocol == 'modbus':
            from lanpwner.protocols.modbus import ModbusModule
            modbus = ModbusModule(debug=args.debug or global_debug)
            if args.discover:
                devices = modbus.discover(subnet=args.subnet)
                print(f'[*] Found {len(devices)} Modbus device(s). Enumerating...')
                report = ReportGenerator()
                enumerate_and_report(modbus, devices, report, debug=args.debug or global_debug, threads=modbus_threads, progress_label='Modbus')
            elif args.enumerate:
                if not args.ip:
                    print('[!] --ip is required for enumeration.')
                    sys.exit(1)
                info = modbus.enumerate(args.ip)
                print(f'[*] Enumeration result for {args.ip}:')
                print(info)
            elif args.write_single_coil:
                if not args.yes_i_am_authorized:
                    print('[!] You must use --yes-i-am-authorized to run this attack.')
                    sys.exit(1)
                if not (args.ip and args.address is not None and args.value is not None):
                    print('[!] --ip, --address, and --value are required.')
                    sys.exit(1)
                result = modbus.write_single_coil(args.ip, args.address, bool(args.value))
                print(result)
            elif args.write_single_register:
                if not args.yes_i_am_authorized:
                    print('[!] You must use --yes-i-am-authorized to run this attack.')
                    sys.exit(1)
                if not (args.ip and args.address is not None and args.value is not None):
                    print('[!] --ip, --address, and --value are required.')
                    sys.exit(1)
                result = modbus.write_single_register(args.ip, args.address, args.value)
                print(result)
            elif args.write_multiple_coils:
                if not args.yes_i_am_authorized:
                    print('[!] You must use --yes-i-am-authorized to run this attack.')
                    sys.exit(1)
                if not (args.ip and args.address is not None and args.values):
                    print('[!] --ip, --address, and --values are required.')
                    sys.exit(1)
                values = [bool(int(v)) for v in args.values.split(',')]
                result = modbus.write_multiple_coils(args.ip, args.address, values)
                print(result)
            elif args.write_multiple_registers:
                if not args.yes_i_am_authorized:
                    print('[!] You must use --yes-i-am-authorized to run this attack.')
                    sys.exit(1)
                if not (args.ip and args.address is not None and args.values):
                    print('[!] --ip, --address, and --values are required.')
                    sys.exit(1)
                values = [int(v) for v in args.values.split(',')]
                result = modbus.write_multiple_registers(args.ip, args.address, values)
                print(result)
            elif args.shell:
                if not args.yes_i_am_authorized:
                    print('[!] You must use --yes-i-am-authorized to run this attack.')
                    sys.exit(1)
                if not (args.ip and args.address is not None and args.value is not None):
                    print('[!] --ip, --address, and --value are required.')
                    sys.exit(1)
                result = modbus.shell(args.ip, args.address, args.value)
                print(result)

        elif args.protocol == 'bacnet':
            from lanpwner.protocols.bacnet import BACnetModule
            bacnet = BACnetModule(debug=args.debug or global_debug)
            if args.discover:
                devices = bacnet.discover(subnet=args.subnet)
                print(f'[*] Found {len(devices)} BACnet device(s). Enumerating...')
                report = ReportGenerator()
                enumerate_and_report(bacnet, devices, report, debug=args.debug or global_debug, threads=bacnet_threads, progress_label='BACnet')
            elif args.enumerate:
                if not args.ip:
                    print('[!] --ip is required for enumeration.')
                    sys.exit(1)
                info = bacnet.enumerate(args.ip)
                print(f'[*] Enumeration result for {args.ip}:')
                print(info)

        elif args.protocol == 'snmp':
            from lanpwner.protocols.snmp import SNMPModule
            snmp = SNMPModule(debug=args.debug or global_debug)
            if args.discover:
                devices = snmp.discover(subnet=args.subnet)
                print(f'[*] Found {len(devices)} SNMP device(s). Enumerating...')
                report = ReportGenerator()
                enumerate_and_report(snmp, devices, report, debug=args.debug or global_debug, threads=snmp_threads, progress_label='SNMP')
            elif args.enumerate:
                if not args.ip:
                    print('[!] --ip is required for enumeration.')
                    sys.exit(1)
                info = snmp.enumerate(args.ip, community=args.community)
                print(f'[*] Enumeration result for {args.ip}:')
                print(info)
            elif args.brute_force:
                if not args.ip:
                    print('[!] --ip is required for brute-force.')
                    sys.exit(1)
                comm = snmp.brute_force_community(args.ip)
                print(f'[*] Brute-force result for {args.ip}: {comm}')

        elif args.protocol == 'sip':
            from lanpwner.protocols.sip import SIPModule
            sip = SIPModule(debug=args.debug or global_debug)
            if args.discover:
                devices = sip.discover(subnet=args.subnet)
                print(f'[*] Found {len(devices)} SIP device(s). Enumerating...')
                report = ReportGenerator()
                enumerate_and_report(sip, devices, report, check_misconfig=False, debug=args.debug or global_debug, threads=sip_threads, progress_label='SIP')
            elif args.enumerate_users:
                if not args.ip:
                    print('[!] --ip is required for user enumeration.')
                    sys.exit(1)
                users = sip.enumerate_users(args.ip)
                print(f'[*] Users found on {args.ip}: {users}')
            elif args.brute_force:
                if not (args.ip and args.user and args.passlist):
                    print('[!] --ip, --user, and --passlist are required for brute-force.')
                    sys.exit(1)
                with open(args.passlist) as pf:
                    passlist = [p.strip() for p in pf if p.strip()]
                pwd = sip.brute_force(args.ip, args.user, passlist)
                print(f'[*] Brute-force result for {args.ip} user {args.user}: {pwd}')
            elif args.spoof_call:
                if not (args.ip and args.from_user and args.to_user):
                    print('[!] --ip, --from-user, and --to-user are required for spoofing.')
                    sys.exit(1)
                result = sip.spoof_call(args.ip, args.from_user, args.to_user)
                print(f'[*] Spoof call result: {result}')

        elif args.protocol == 'scan':
            # Batch scan mode: run all discovery/enumeration modules in parallel
            print('[*] Running batch scan of all supported protocols (multi-threaded)...')
            report = ReportGenerator()
            scan_jobs = []
            with ThreadPoolExecutor(max_workers=threads) as executor:
                # UPnP
                upnp = UPnPModule(debug=args.debug or global_debug)
                scan_jobs.append(executor.submit(lambda: ("upnp", upnp, upnp.discover())))
                # Bonjour
                bonjour = BonjourModule()
                scan_jobs.append(executor.submit(lambda: ("bonjour", bonjour, bonjour.discover())))
                # Modbus
                from lanpwner.protocols.modbus import ModbusModule
                modbus = ModbusModule(debug=args.debug or global_debug)
                scan_jobs.append(executor.submit(lambda: ("modbus", modbus, modbus.discover())))
                # BACnet
                from lanpwner.protocols.bacnet import BACnetModule
                bacnet = BACnetModule(debug=args.debug or global_debug)
                scan_jobs.append(executor.submit(lambda: ("bacnet", bacnet, bacnet.discover())))
                # SNMP
                from lanpwner.protocols.snmp import SNMPModule
                snmp = SNMPModule(debug=args.debug or global_debug)
                scan_jobs.append(executor.submit(lambda: ("snmp", snmp, snmp.discover())))
                # SIP
                from lanpwner.protocols.sip import SIPModule
                sip = SIPModule(debug=args.debug or global_debug)
                scan_jobs.append(executor.submit(lambda: ("sip", sip, sip.discover())))
                for fut in as_completed(scan_jobs):
                    proto, module, devices = fut.result()
                    print(f'[*] {proto.upper()}: {len(devices)} device(s) found. Enumerating...')
                    # Use per-protocol thread tuning
                    proto_threads = threads
                    if proto == 'modbus':
                        proto_threads = modbus_threads
                    elif proto == 'snmp':
                        proto_threads = snmp_threads
                    elif proto == 'bacnet':
                        proto_threads = bacnet_threads
                    elif proto == 'sip':
                        proto_threads = sip_threads
                    enumerate_and_report(module, devices, report, check_misconfig=(proto!="bonjour" and proto!="sip"), debug=args.debug or global_debug, threads=proto_threads, progress_label=proto.upper())
            print(f'[*] Batch scan complete. {report.discovery_count()} devices found, {report.vulnerability_count()} vulnerabilities detected.')

        elif args.protocol == 'cast':
            cast = CastModule(debug=args.debug)
            loop = asyncio.get_event_loop()

            # Discover devices first
            print("[*] Discovering cast-capable devices...")
            devices = loop.run_until_complete(cast.discover_devices())
            print(f"[*] Found {len(devices)} device(s)")

            if args.detect_sessions:
                print("[*] Detecting active casting sessions...")
                sessions = loop.run_until_complete(cast.detect_sessions())
                if sessions:
                    print(f"[*] Found {len(sessions)} active session(s):")
                    for session in sessions:
                        print(f"\nDevice: {session['device_name']} ({session['device_type']})")
                        print(f"Status: {session['status']}")
                        print(f"App: {session['app']}")
                        print(f"Media Type: {session['media_type']}")
                        print(f"Progress: {session['current_time']}/{session['duration']} seconds")
                        print(f"Volume: {session['volume']}")
                else:
                    print("[*] No active casting sessions found")

            elif args.hijack:
                if not args.target:
                    print("[!] Error: --target is required for hijack")
                    sys.exit(1)
                if not args.video_url:
                    print("[!] Error: --video-url is required for hijack")
                    sys.exit(1)

                print(f"[*] Attempting to hijack session on {args.target}...")
                success = loop.run_until_complete(cast.hijack_session(args.target, args.video_url))
                if not success:
                    print("[!] Failed to hijack session")
                    sys.exit(1)

            elif args.broadcast:
                if not args.video_url:
                    print("[!] Error: --video-url is required for broadcast")
                    sys.exit(1)

                print("[*] Broadcasting video to all discovered devices...")
                results = loop.run_until_complete(cast.broadcast_to_all(args.video_url))
                print("\nBroadcast Results:")
                for result in results:
                    status = "✓" if result['status'] == 'success' else "✗"
                    print(f"{status} {result['device']} ({result['type']})")
                    if result['status'] == 'failed':
                        print(f"   Error: {result['error']}")

        else:
            print('[!] No valid protocol selected.')
            sys.exit(1)

    except Exception as e:
        print(f'[!] Fatal error: {e}')
        sys.exit(1)

if __name__ == "__main__":
    main()
