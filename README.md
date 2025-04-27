# LANPWNER: Offensive LAN Protocol & Device Framework

## Overview
LANPWNER is an advanced Python framework for discovering, enumerating, auditing, and ethically attacking LAN protocols and devices. It supports a wide range of protocols (UPnP, Bonjour/mDNS, ARP, DHCP, RTSP, casting protocols, and more) and is designed for authorized security testing, red teaming, and research.

**LEGAL DISCLAIMER:**
> This tool is for authorized security testing and educational use only. Unauthorized use against networks you do not own or have explicit permission to test is illegal and unethical.

---

## Features
- **Discovery & Enumeration:**
  - UPnP/SSDP, Bonjour/mDNS (AirPlay, Chromecast, DIAL, DLNA, Smart TVs, IoT, mobile devices)
  - Passive device and protocol detection (DHCP, ARP, RTSP, SMB, etc.)
  - Dynamic subnet detection and interface selection
- **Vulnerability & Misconfiguration Checks:**
  - Public CVE references, default credentials, open control URLs, and more
- **Attack Modules:**
  - DHCP: Starvation, spoofing, inform flood, option overload, lease query, decline/release flood, relay spoof
  - ARP: Spoofing, request/reply flood, cache poisoning, gratuitous, reactive, malformed, scan, storm
  - RTSP: Discovery, enumeration, weak/default credential audit, fingerprinting, DoS
  - **Casting/Mobile:** Detect, hijack, broadcast, and manage sessions on TVs, media servers, and mobile devices (AirPlay, Chromecast, DIAL, UPnP AVTransport)
- **Advanced Session Management:**
  - Play, queue, pause, stop, and query status for supported cast/mobile protocols
- **Reporting:**
  - HTML/JSON output, CVE/standards references, device inventory
- **Extensible:**
  - Modular protocol support, easy to add new attacks or device types

---

## Usage Examples

### General
```bash
python3 lanpwner.py --help
```

### Discover and Enumerate Devices
```bash
python3 lanpwner.py upnp --timeout 10 --debug
python3 lanpwner.py bonjour --timeout 10 --debug
python3 lanpwner.py sniff --interface eth0 --timeout 20 --debug
```

### DHCP/ARP Attacks
```bash
python3 lanpwner.py dhcp --starvation --interface eth0 --count 100 --yes-i-am-authorized
python3 lanpwner.py arp --spoof --interface eth0 --target-ip 192.168.1.10 --spoof-ip 192.168.1.1 --yes-i-am-authorized
```

### RTSP Auditing
```bash
python3 lanpwner.py rtsp --discover --timeout 10
python3 lanpwner.py rtsp --enumerate --endpoint rtsp://192.168.1.100:554
```

### Cast/Mobile Device Attacks & Session Management
#### Detect Cast/Mobile Devices and Sessions
```bash
python3 lanpwner.py cast --detect-sessions --debug
```
#### Hijack or Broadcast Video (Play, Pause, Stop, Status)
```bash
# Play a video on all detected devices
python3 lanpwner.py cast --broadcast --video-url "http://example.com/video.mp4"

# Pause/Stop playback on all devices
python3 lanpwner.py cast --broadcast --video-url "http://example.com/video.mp4" --action stop

# Query status of all sessions
python3 lanpwner.py cast --broadcast --video-url "http://example.com/video.mp4" --action status
```

#### Target a Specific Device (Hijack)
```bash
python3 lanpwner.py cast --hijack --target "Living Room TV" --video-url "http://example.com/video.mp4" --action play
```

### Modbus, BACnet, SNMP, SIP, and Batch Scan

#### Modbus (ICS/SCADA)
```bash
# Discover Modbus devices
python3 lanpwner.py modbus --discover --subnet 192.168.1.0/24
# Enumerate a Modbus device
python3 lanpwner.py modbus --enumerate --ip 192.168.1.100
# Offensive attacks (DANGEROUS, authorized use only)
python3 lanpwner.py modbus --write-single-register --ip 192.168.1.100 --address 10 --value 1234 --yes-i-am-authorized
python3 lanpwner.py modbus --shell --ip 192.168.1.100 --address 10 --value 31337 --yes-i-am-authorized
```

#### BACnet (Building Automation)
```bash
python3 lanpwner.py bacnet --discover --subnet 192.168.1.0/24
python3 lanpwner.py bacnet --enumerate --ip 192.168.1.150
```

#### SNMP (Network Devices)
```bash
python3 lanpwner.py snmp --discover --subnet 192.168.1.0/24
python3 lanpwner.py snmp --enumerate --ip 192.168.1.1 --community public
python3 lanpwner.py snmp --brute-force --ip 192.168.1.1
```

#### SIP (VoIP/Phones)
```bash
python3 lanpwner.py sip --discover --subnet 192.168.1.0/24
python3 lanpwner.py sip --enumerate-users --ip 192.168.1.200
python3 lanpwner.py sip --brute-force --ip 192.168.1.200 --user admin --passlist passwords.txt
python3 lanpwner.py sip --spoof-call --ip 192.168.1.200 --from-user attacker --to-user victim
```

#### Batch Scan (All Protocols)
```bash
python3 lanpwner.py scan --debug
```

---

## Protocols & Device Support
- **UPnP/SSDP:** MediaRenderer, MediaServer, DIAL, AVTransport, IoT, Smart TVs, some mobile apps
- **Bonjour/mDNS:** AirPlay (iOS), Chromecast (Android), DIAL, mobile devices
- **DHCP/ARP:** Host inventory, attacks, MAC vendor detection
- **RTSP:** Cameras, NVRs, media servers
- **Casting/Mobile:**
  - **AirPlay:** Play, pause, stop, status (iOS, Apple TV)
  - **Chromecast/Google Cast:** Play, stop, status (Android, Google TV)
  - **DIAL:** Play, stop, status (Smart TVs, some mobile apps)
  - **UPnP AVTransport:** Play, stop, status (DLNA, Smart TVs, some mobile apps)

---

## Ethical Use
- Only use LANPWNER on networks and devices you own or have explicit written authorization to test.
- Always notify stakeholders and follow responsible disclosure practices.
- The authors are not responsible for misuse or damages.

---

## Requirements
- Python 3.7+
- See `requirements.txt` for dependencies (requests, scapy, zeroconf, netifaces, etc.)

---

## Contributing
- Pull requests, issues, and feature suggestions are welcome!
- See `CONTRIBUTING.md` for guidelines.

---

## License
See `LICENSE` for details.

---

## Advanced Features
- **Risk Scoring:** Each device and finding is scored for risk (planned: more advanced scoring and prioritization).
- **Multi-threading:** Planned for faster batch scans and parallel enumeration.
- **Dynamic Protocol Loading:** Planned for future releases to allow plug-and-play protocol modules.