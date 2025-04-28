# LANPWNER: Offensive LAN Protocol & Device Framework

## Overview
LANPWNER is an advanced Python framework for discovering, enumerating, auditing, and ethically attacking LAN protocols and devices. It supports a wide range of protocols and is designed for authorized security testing, red teaming, and research.

**LEGAL DISCLAIMER:**
> This tool is for authorized security testing and educational use only. Unauthorized use against networks you do not own or have explicit permission to test is illegal and unethical.

---

## Protocol Modules & Attack Capabilities

### UPnP/SSDP Module
- **Discovery & Enumeration:**
  - Device and service discovery
  - MediaRenderer and MediaServer detection
  - DIAL service enumeration
  - AVTransport capabilities
  - IoT and Smart TV detection
- **Attacks:**
  - Service control exploitation
  - Default credential testing
  - Unauthorized control attempts
  - Service flooding
```bash
python3 lanpwner.py upnp --timeout 10 --debug
python3 lanpwner.py upnp --enumerate --target 192.168.1.100
```

### Bonjour/mDNS Module
- **Discovery & Enumeration:**
  - AirPlay devices (iOS)
  - Chromecast devices (Android)
  - DIAL protocol services
  - Mobile device detection
- **Attacks:**
  - Service hijacking
  - Unauthorized broadcasting
  - Session manipulation
```bash
python3 lanpwner.py bonjour --timeout 10 --debug
python3 lanpwner.py bonjour --enumerate --target 192.168.1.100
```

### DHCP Module
- **Discovery & Enumeration:**
  - DHCP server detection
  - Lease information gathering
  - Option enumeration
- **Attacks:**
  - Starvation attacks
  - Spoofing
  - Inform flood
  - Option overload
  - Lease query abuse
  - Decline/release flood
  - Relay spoofing
```bash
python3 lanpwner.py dhcp --discover
python3 lanpwner.py dhcp --starvation --interface eth0 --count 100 --yes-i-am-authorized
```

### ARP Module
- **Discovery & Enumeration:**
  - Host discovery
  - MAC vendor detection
  - Network mapping
- **Attacks:**
  - ARP spoofing
  - Request/reply flooding
  - Cache poisoning
  - Gratuitous ARP
  - Reactive poisoning
  - Malformed packets
  - ARP scan
  - ARP storm
```bash
python3 lanpwner.py arp --discover
python3 lanpwner.py arp --spoof --interface eth0 --target-ip 192.168.1.10 --spoof-ip 192.168.1.1 --yes-i-am-authorized
```

### RTSP Module
- **Discovery & Enumeration:**
  - Camera detection
  - NVR discovery
  - Media server identification
  - Stream capability detection
- **Attacks:**
  - Credential bruteforce
  - Stream hijacking
  - Denial of Service
  - Unauthorized access attempts
```bash
python3 lanpwner.py rtsp --discover --timeout 10
python3 lanpwner.py rtsp --enumerate --endpoint rtsp://192.168.1.100:554
```

### Casting/Mobile Device Module
- **Discovery & Enumeration:**
  - AirPlay device detection
  - Chromecast discovery
  - DIAL protocol scanning
  - UPnP AVTransport detection
- **Attacks & Control:**
  - Session hijacking
  - Unauthorized broadcasting
  - Playback manipulation
  - Status monitoring
```bash
python3 lanpwner.py cast --detect-sessions --debug
python3 lanpwner.py cast --broadcast --video-url "http://example.com/video.mp4"
python3 lanpwner.py cast --hijack --target "Living Room TV" --video-url "http://example.com/video.mp4" --action play
```

### Modbus (ICS/SCADA) Module
- **Discovery & Enumeration:**
  - Device discovery
  - Register enumeration
  - Function code scanning
- **Attacks:**
  - Register manipulation
  - Function code abuse
  - Shell injection attempts
```bash
python3 lanpwner.py modbus --discover --subnet 192.168.1.0/24
python3 lanpwner.py modbus --enumerate --ip 192.168.1.100
python3 lanpwner.py modbus --write-single-register --ip 192.168.1.100 --address 10 --value 1234 --yes-i-am-authorized
```

### BACnet Module
- **Discovery & Enumeration:**
  - Device discovery
  - Object enumeration
  - Property scanning
- **Attacks:**
  - Property manipulation
  - Service abuse
  - Unauthorized control
```bash
python3 lanpwner.py bacnet --discover --subnet 192.168.1.0/24
python3 lanpwner.py bacnet --enumerate --ip 192.168.1.150
```

### SNMP Module
- **Discovery & Enumeration:**
  - Device discovery
  - Community string testing
  - MIB walking
- **Attacks:**
  - Community string bruteforce
  - Write access abuse
  - Information disclosure
```bash
python3 lanpwner.py snmp --discover --subnet 192.168.1.0/24
python3 lanpwner.py snmp --enumerate --ip 192.168.1.1 --community public
python3 lanpwner.py snmp --brute-force --ip 192.168.1.1
```

### SIP Module
- **Discovery & Enumeration:**
  - VoIP device detection
  - User enumeration
  - Extension scanning
- **Attacks:**
  - Credential bruteforce
  - Call spoofing
  - Registration hijacking
```bash
python3 lanpwner.py sip --discover --subnet 192.168.1.0/24
python3 lanpwner.py sip --enumerate-users --ip 192.168.1.200
python3 lanpwner.py sip --brute-force --ip 192.168.1.200 --user admin --passlist passwords.txt
```

## Batch Operations
```bash
# Scan all supported protocols
python3 lanpwner.py scan --debug
```

## Requirements
- Python 3.7+
- See `requirements.txt` for dependencies (requests, scapy, zeroconf, netifaces, etc.)

## Ethical Use
- Only use LANPWNER on networks and devices you own or have explicit written authorization to test
- Always notify stakeholders and follow responsible disclosure practices
- The authors are not responsible for misuse or damages

## Contributing
- Pull requests, issues, and feature suggestions are welcome!
- See `CONTRIBUTING.md` for guidelines

## License
See `LICENSE` for details

## Advanced Features
- **Risk Scoring:** Each device and finding is scored for risk
- **Multi-threading:** Parallel scanning and enumeration capabilities
- **Dynamic Protocol Loading:** Plug-and-play protocol modules
- **Comprehensive Reporting:** HTML/JSON output with CVE references