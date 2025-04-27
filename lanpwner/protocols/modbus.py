import socket
from typing import List, Dict, Any

class ModbusModule:
    """
    Modbus protocol support: discovery, enumeration, CVE/misconfig checks.
    """
    def __init__(self, timeout: int = 2, debug: bool = False):
        self.timeout = timeout
        self.debug = debug

    def discover(self, subnet: str = '192.168.1.0/24') -> List[Dict[str, Any]]:
        """Scan subnet for Modbus devices (TCP/502)."""
        found = []
        base = '.'.join(subnet.split('.')[:3]) + '.'
        mb_req = b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01'  # Read Holding Register 0
        for i in range(1, 255):
            ip = f'{base}{i}'
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                s.connect((ip, 502))
                s.sendall(mb_req)
                data = s.recv(1024)
                if data:
                    found.append({'ip': ip, 'raw': data})
                    if self.debug:
                        print(f'[DEBUG] Modbus response from {ip}')
            except Exception:
                pass
            s.close()
        return found

    def enumerate(self, ip: str) -> Dict[str, Any]:
        """Read Modbus device info using function code 43/14 (Read Device Identification) and 17 (Report Slave ID)."""
        info = {'ip': ip, 'device_id': {}, 'slave_id': {}, 'errors': []}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, 502))
            # Function code 43/14: Read Device Identification (Basic)
            # MBAP Header: Transaction ID (2), Protocol ID (2), Length (2), Unit ID (1)
            # PDU: Function (1), MEI Type (1), Read Device ID Code (1), Object ID (1)
            # Transaction ID: 0x0001, Protocol ID: 0x0000, Length: 0x0006, Unit ID: 0x01
            mbap = b'\x00\x01\x00\x00\x00\x06\x01'
            pdu = b'\x2b\x0e\x01\x00'  # 43, 14, 1 (basic), 0 (vendor name)
            req = mbap + pdu
            s.sendall(req)
            data = s.recv(256)
            if data and data[7] == 0x2b and data[8] == 0x0e:
                # Parse Device Identification response
                conformity = data[10]
                more_follows = data[11]
                next_obj_id = data[12]
                num_objects = data[13]
                pos = 14
                for _ in range(num_objects):
                    if pos+2 > len(data):
                        break
                    obj_id = data[pos]
                    obj_len = data[pos+1]
                    obj_val = data[pos+2:pos+2+obj_len].decode(errors='ignore')
                    info['device_id'][obj_id] = obj_val
                    pos += 2 + obj_len
                if self.debug:
                    print(f"[DEBUG] Modbus 43/14 Device ID from {ip}: {info['device_id']}")
            else:
                info['errors'].append('No valid 43/14 response')
            # Optionally, try function code 17: Report Slave ID
            mbap2 = b'\x00\x02\x00\x00\x00\x06\x01'
            pdu2 = b'\x11\x00\x00\x00'  # 17, 0, 0, 0 (unit id 0)
            req2 = mbap2 + pdu2
            s.sendall(req2)
            data2 = s.recv(256)
            if data2 and data2[7] == 0x11:
                slave_id_len = data2[8]
                slave_id = data2[9:9+slave_id_len]
                run_status = data2[9+slave_id_len]
                info['slave_id'] = {
                    'raw': slave_id.hex(),
                    'run_status': run_status
                }
                if self.debug:
                    print(f"[DEBUG] Modbus 17 Slave ID from {ip}: {info['slave_id']}")
            else:
                info['errors'].append('No valid 17 response')
            s.close()
        except Exception as e:
            info['errors'].append(str(e))
        return info

    def check_misconfigurations(self, info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for unauthenticated access, known CVEs (stub)."""
        findings = []
        findings.append({'title': 'Unauthenticated Modbus', 'severity': 'High', 'description': 'Modbus device responds without authentication.', 'cve': ['CVE-2019-10953']})
        # Add more CVE checks as needed
        return findings

    def write_single_coil(self, ip: str, address: int, value: bool) -> Dict[str, Any]:
        """[DANGEROUS] Write a single coil (on/off) to a Modbus device. Requires authorization!"""
        result = {'ip': ip, 'address': address, 'value': value, 'success': False, 'error': None}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, 502))
            # MBAP: Transaction ID, Protocol ID, Length, Unit ID
            mbap = b'\x00\x03\x00\x00\x00\x06\x01'
            # PDU: Function 5, Address (2), Value (2)
            val = b'\xff\x00' if value else b'\x00\x00'
            pdu = b'\x05' + address.to_bytes(2, 'big') + val
            req = mbap + pdu
            s.sendall(req)
            resp = s.recv(256)
            if resp[7] == 0x05:
                result['success'] = True
            if self.debug:
                print(f"[DEBUG] Write Single Coil to {ip} addr {address}: {value} -> {result['success']}")
            s.close()
        except Exception as e:
            result['error'] = str(e)
        return result

    def write_single_register(self, ip: str, address: int, value: int) -> Dict[str, Any]:
        """[DANGEROUS] Write a single holding register to a Modbus device. Requires authorization!"""
        result = {'ip': ip, 'address': address, 'value': value, 'success': False, 'error': None}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, 502))
            mbap = b'\x00\x04\x00\x00\x00\x06\x01'
            pdu = b'\x06' + address.to_bytes(2, 'big') + value.to_bytes(2, 'big')
            req = mbap + pdu
            s.sendall(req)
            resp = s.recv(256)
            if resp[7] == 0x06:
                result['success'] = True
            if self.debug:
                print(f"[DEBUG] Write Single Register to {ip} addr {address}: {value} -> {result['success']}")
            s.close()
        except Exception as e:
            result['error'] = str(e)
        return result

    def write_multiple_coils(self, ip: str, address: int, values: list) -> Dict[str, Any]:
        """[DANGEROUS] Write multiple coils to a Modbus device. Requires authorization!"""
        result = {'ip': ip, 'address': address, 'values': values, 'success': False, 'error': None}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, 502))
            count = len(values)
            byte_count = (count + 7) // 8
            coil_bytes = bytearray(byte_count)
            for i, v in enumerate(values):
                if v:
                    coil_bytes[i // 8] |= (1 << (i % 8))
            mbap = b'\x00\x05\x00\x00\x00' + (7 + byte_count).to_bytes(2, 'big') + b'\x01'
            pdu = b'\x0f' + address.to_bytes(2, 'big') + count.to_bytes(2, 'big') + bytes([byte_count]) + bytes(coil_bytes)
            req = mbap + pdu
            s.sendall(req)
            resp = s.recv(256)
            if resp[7] == 0x0f:
                result['success'] = True
            if self.debug:
                print(f"[DEBUG] Write Multiple Coils to {ip} addr {address}: {values} -> {result['success']}")
            s.close()
        except Exception as e:
            result['error'] = str(e)
        return result

    def write_multiple_registers(self, ip: str, address: int, values: list) -> Dict[str, Any]:
        """[DANGEROUS] Write multiple holding registers to a Modbus device. Requires authorization!"""
        result = {'ip': ip, 'address': address, 'values': values, 'success': False, 'error': None}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, 502))
            count = len(values)
            byte_count = count * 2
            mbap = b'\x00\x06\x00\x00\x00' + (7 + byte_count).to_bytes(2, 'big') + b'\x01'
            pdu = b'\x10' + address.to_bytes(2, 'big') + count.to_bytes(2, 'big') + bytes([byte_count])
            for v in values:
                pdu += v.to_bytes(2, 'big')
            req = mbap + pdu
            s.sendall(req)
            resp = s.recv(256)
            if resp[7] == 0x10:
                result['success'] = True
            if self.debug:
                print(f"[DEBUG] Write Multiple Registers to {ip} addr {address}: {values} -> {result['success']}")
            s.close()
        except Exception as e:
            result['error'] = str(e)
        return result

    def shell(self, ip: str, address: int, command_value: int) -> Dict[str, Any]:
        """[DANGEROUS] Simulate shell execution by writing a value to a register. This does NOT execute OS commands, but demonstrates remote control via Modbus. Requires authorization!"""
        # In real attacks, this could trigger a PLC logic change or unsafe state.
        return self.write_single_register(ip, address, command_value) 