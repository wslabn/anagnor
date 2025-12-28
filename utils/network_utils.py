import socket
import ipaddress
import netifaces
from typing import List
import subprocess
import platform

class NetworkUtils:
    @staticmethod
    def get_local_networks() -> List[str]:
        """Discover local network ranges"""
        networks = []
        
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info.get('addr')
                        netmask = addr_info.get('netmask')
                        
                        if ip and netmask and not ip.startswith('127.'):
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            networks.append(str(network))
            except Exception:
                continue
                
        return list(set(networks))
    
    @staticmethod
    def is_host_alive(ip: str, timeout: int = 1) -> bool:
        """Check if host responds to ping"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W' if platform.system().lower() == 'windows' else '-w', str(timeout), ip]
        
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout + 1)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
    
    @staticmethod
    def resolve_hostname(ip: str) -> str:
        """Resolve IP to hostname"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ip
    
    @staticmethod
    def get_mac_address(ip: str) -> str:
        """Get MAC address for IP (Linux/Unix only)"""
        try:
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
        except Exception:
            pass
        return "Unknown"