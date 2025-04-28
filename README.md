# LANPWNER: Offensive LAN Protocol & Device Framework

[![GitHub license](https://img.shields.io/github/license/rfs85/LANPWNER)](https://github.com/rfs85/LANPWNER/blob/main/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/downloads/)
[![GitHub issues](https://img.shields.io/github/issues/rfs85/LANPWNER)](https://github.com/rfs85/LANPWNER/issues)
[![GitHub stars](https://img.shields.io/github/stars/rfs85/LANPWNER)](https://github.com/rfs85/LANPWNER/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/rfs85/LANPWNER)](https://github.com/rfs85/LANPWNER/network)

<div align="center">
  <a href="https://github.com/rfs85/LANPWNER">
    <img src="https://raw.githubusercontent.com/rfs85/LANPWNER/main/docs/logo.png" alt="LANPWNER Logo" width="200" height="200">
  </a>

  <p align="center">
    Advanced Python framework for LAN protocol security testing and device enumeration
    <br />
    <a href="https://github.com/rfs85/LANPWNER/wiki"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/rfs85/LANPWNER/issues/new?template=bug_report.md">Report Bug</a>
    ·
    <a href="https://github.com/rfs85/LANPWNER/issues/new?template=feature_request.md">Request Feature</a>
  </p>
</div>

## 📖 Overview

LANPWNER is an advanced Python framework for discovering, enumerating, auditing, and ethically attacking LAN protocols and devices. It supports a wide range of protocols and is designed for authorized security testing, red teaming, and research.

> ⚠️ **LEGAL DISCLAIMER:** This tool is for authorized security testing and educational use only. Unauthorized use against networks you do not own or have explicit permission to test is illegal and unethical.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/rfs85/LANPWNER.git

# Navigate to the directory
cd LANPWNER

# Install dependencies
pip install -r requirements.txt

# Run help
python3 lanpwner.py --help
```

## 🛠️ Protocol Modules & Attack Capabilities

### 📡 UPnP/SSDP Module
<details>
<summary>Click to expand</summary>

#### Discovery & Enumeration
- Device and service discovery
- MediaRenderer and MediaServer detection
- DIAL service enumeration
- AVTransport capabilities
- IoT and Smart TV detection

#### Attacks
- Service control exploitation
- Default credential testing
- Unauthorized control attempts
- Service flooding

```bash
python3 lanpwner.py upnp --timeout 10 --debug
python3 lanpwner.py upnp --enumerate --target 192.168.1.100
```
</details>

### 🌐 Bonjour/mDNS Module
<details>
<summary>Click to expand</summary>

#### Discovery & Enumeration
- AirPlay devices (iOS)
- Chromecast devices (Android)
- DIAL protocol services
- Mobile device detection

#### Attacks
- Service hijacking
- Unauthorized broadcasting
- Session manipulation

```bash
python3 lanpwner.py bonjour --timeout 10 --debug
python3 lanpwner.py bonjour --enumerate --target 192.168.1.100
```
</details>

### 🔄 DHCP Module
<details>
<summary>Click to expand</summary>

#### Discovery & Enumeration
- DHCP server detection
- Lease information gathering
- Option enumeration

#### Attacks
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
</details>

### 🔍 ARP Module
<details>
<summary>Click to expand</summary>

#### Discovery & Enumeration
- Host discovery
- MAC vendor detection
- Network mapping

#### Attacks
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
</details>

### 📹 RTSP Module
<details>
<summary>Click to expand</summary>

#### Discovery & Enumeration
- Camera detection
- NVR discovery
- Media server identification
- Stream capability detection

#### Attacks
- Credential bruteforce
- Stream hijacking
- Denial of Service
- Unauthorized access attempts

```bash
python3 lanpwner.py rtsp --discover --timeout 10
python3 lanpwner.py rtsp --enumerate --endpoint rtsp://192.168.1.100:554
```
</details>

### 📱 Casting/Mobile Device Module
<details>
<summary>Click to expand</summary>

#### Discovery & Enumeration
- AirPlay device detection
- Chromecast discovery
- DIAL protocol scanning
- UPnP AVTransport detection

#### Attacks & Control
- Session hijacking
- Unauthorized broadcasting
- Playback manipulation
- Status monitoring

```bash
python3 lanpwner.py cast --detect-sessions --debug
python3 lanpwner.py cast --broadcast --video-url "http://example.com/video.mp4"
python3 lanpwner.py cast --hijack --target "Living Room TV" --video-url "http://example.com/video.mp4" --action play
```
</details>

### 🏭 Modbus (ICS/SCADA) Module
<details>
<summary>Click to expand</summary>

#### Discovery & Enumeration
- Device discovery
- Register enumeration
- Function code scanning

#### Attacks
- Register manipulation
- Function code abuse
- Shell injection attempts

```bash
python3 lanpwner.py modbus --discover --subnet 192.168.1.0/24
python3 lanpwner.py modbus --enumerate --ip 192.168.1.100
python3 lanpwner.py modbus --write-single-register --ip 192.168.1.100 --address 10 --value 1234 --yes-i-am-authorized
```
</details>

### 🏢 BACnet Module
<details>
<summary>Click to expand</summary>

#### Discovery & Enumeration
- Device discovery
- Object enumeration
- Property scanning

#### Attacks
- Property manipulation
- Service abuse
- Unauthorized control

```bash
python3 lanpwner.py bacnet --discover --subnet 192.168.1.0/24
python3 lanpwner.py bacnet --enumerate --ip 192.168.1.150
```
</details>

### 📊 SNMP Module
<details>
<summary>Click to expand</summary>

#### Discovery & Enumeration
- Device discovery
- Community string testing
- MIB walking

#### Attacks
- Community string bruteforce
- Write access abuse
- Information disclosure

```bash
python3 lanpwner.py snmp --discover --subnet 192.168.1.0/24
python3 lanpwner.py snmp --enumerate --ip 192.168.1.1 --community public
python3 lanpwner.py snmp --brute-force --ip 192.168.1.1
```
</details>

### ☎️ SIP Module
<details>
<summary>Click to expand</summary>

#### Discovery & Enumeration
- VoIP device detection
- User enumeration
- Extension scanning

#### Attacks
- Credential bruteforce
- Call spoofing
- Registration hijacking

```bash
python3 lanpwner.py sip --discover --subnet 192.168.1.0/24
python3 lanpwner.py sip --enumerate-users --ip 192.168.1.200
python3 lanpwner.py sip --brute-force --ip 192.168.1.200 --user admin --passlist passwords.txt
```
</details>

## 🔄 Batch Operations
```bash
# Scan all supported protocols
python3 lanpwner.py scan --debug
```

## ⚙️ Requirements
- Python 3.7+
- See `requirements.txt` for dependencies

## 🔒 Ethical Use
- Only use LANPWNER on networks and devices you own or have explicit written authorization to test
- Always notify stakeholders and follow responsible disclosure practices
- The authors are not responsible for misuse or damages

## 🤝 Contributing
We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License
Distributed under the MIT License. See `LICENSE` for more information.

## 🌟 Advanced Features
- **Risk Scoring:** Each device and finding is scored for risk
- **Multi-threading:** Parallel scanning and enumeration capabilities
- **Dynamic Protocol Loading:** Plug-and-play protocol modules
- **Comprehensive Reporting:** HTML/JSON output with CVE references

## 📞 Contact & Support
- GitHub Repository: [https://github.com/rfs85/LANPWNER](https://github.com/rfs85/LANPWNER)
- Issue Tracker: [https://github.com/rfs85/LANPWNER/issues](https://github.com/rfs85/LANPWNER/issues)

---
<div align="center">
Made with ❤️ by the LANPWNER Team
</div>