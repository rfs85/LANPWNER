import socket
from typing import List, Dict, Any, Optional

class SIPModule:
    """
    SIP protocol support: discovery, user enumeration, brute-force, call spoofing.
    """
    def __init__(self, timeout: int = 2, user_list: Optional[List[str]] = None, debug: bool = False):
        self.timeout = timeout
        self.user_list = user_list or ['100', '101', 'admin', 'user']
        self.debug = debug

    def discover(self, subnet: str = '192.168.1.0/24') -> List[Dict[str, Any]]:
        """Scan subnet for SIP devices (UDP/5060)."""
        found = []
        base = '.'.join(subnet.split('.')[:3]) + '.'
        sip_options = b"OPTIONS sip:user@domain SIP/2.0\r\nVia: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-1\r\nFrom: <sip:user@domain>\r\nTo: <sip:user@domain>\r\nCall-ID: 1234567890@1.2.3.4\r\nCSeq: 1 OPTIONS\r\nContact: <sip:user@1.2.3.4>\r\nMax-Forwards: 70\r\nUser-Agent: LANPWNER\r\nContent-Length: 0\r\n\r\n"
        for i in range(1, 255):
            ip = f'{base}{i}'
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            try:
                s.sendto(sip_options, (ip, 5060))
                data, _ = s.recvfrom(1024)
                if b'SIP/2.0' in data:
                    found.append({'ip': ip, 'raw': data})
                    if self.debug:
                        print(f'[DEBUG] SIP response from {ip}')
            except Exception:
                pass
            s.close()
        return found

    def enumerate_users(self, ip: str) -> List[str]:
        """Try to enumerate SIP users/extensions (stub)."""
        # Real implementation would send REGISTER/INVITE for each user and parse responses
        found = []
        for user in self.user_list:
            # Stub: just pretend to find some users
            if user in ['100', '101', 'admin']:
                found.append(user)
        return found

    def brute_force(self, ip: str, user: str, passlist: List[str]) -> Optional[str]:
        """Try to brute-force SIP REGISTER for a user (stub)."""
        # Real implementation would send REGISTER with each password
        for pwd in passlist:
            # Stub: pretend 'password' is always correct
            if pwd == 'password':
                return pwd
        return None

    def spoof_call(self, ip: str, from_user: str, to_user: str) -> bool:
        """Send a spoofed SIP INVITE (stub)."""
        # Real implementation would craft and send INVITE
        print(f'[!] (Stub) Would send spoofed INVITE from {from_user} to {to_user} at {ip}')
        return True 