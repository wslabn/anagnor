import nmap
import requests
import logging
from typing import Dict, List, Any
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.network_utils import NetworkUtils

class DarkHardwareScanner:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        
    def scan(self, networks: List[str]) -> Dict[str, Any]:
        """Scan for IoT devices, printers, and other dark hardware"""
        results = {
            'iot_devices': [],
            'printers': [],
            'voip_phones': [],
            'cameras': [],
            'discovered_devices': []
        }
        
        # Discover all devices with detailed scanning
        all_devices = []
        for network in networks:
            devices = self._detailed_device_scan(network)
            all_devices.extend(devices)
            
        results['discovered_devices'] = all_devices
        
        # Categorize devices
        results['iot_devices'] = self._identify_iot_devices(all_devices)
        results['printers'] = self._identify_printers(all_devices)
        results['voip_phones'] = self._identify_voip_phones(all_devices)
        results['cameras'] = self._identify_cameras(all_devices)
        
        return results
    
    def _detailed_device_scan(self, network: str) -> List[Dict[str, Any]]:
        """Perform detailed scan to identify device types"""
        self.logger.info(f"Detailed scanning network: {network}")
        
        try:
            # Scan common ports for device identification
            common_ports = self.config.get_list('port_scan.common_ports')
            port_range = ','.join(map(str, common_ports))
            
            self.nm.scan(hosts=network, ports=port_range, arguments='-sS -O --version-detection')
            
            devices = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    device = self._analyze_host(host)
                    devices.append(device)
                    
            return devices
            
        except Exception as e:
            self.logger.error(f"Detailed scan failed for {network}: {e}")
            return []
    
    def _analyze_host(self, host: str) -> Dict[str, Any]:
        """Analyze individual host for device characteristics"""
        host_info = self.nm[host]
        
        device = {
            'ip': host,
            'hostname': NetworkUtils.resolve_hostname(host),
            'mac': NetworkUtils.get_mac_address(host),
            'os_guess': self._get_os_guess(host_info),
            'open_ports': [],
            'services': [],
            'device_type': 'unknown',
            'vendor': self._get_vendor_from_mac(NetworkUtils.get_mac_address(host))
        }
        
        # Analyze open ports and services
        for protocol in host_info.all_protocols():
            ports = host_info[protocol].keys()
            for port in ports:
                port_info = host_info[protocol][port]
                if port_info['state'] == 'open':
                    device['open_ports'].append(port)
                    service_info = {
                        'port': port,
                        'service': port_info.get('name', ''),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', '')
                    }
                    device['services'].append(service_info)
        
        # Try to get additional info via HTTP
        device.update(self._probe_http_services(host, device['open_ports']))
        
        return device
    
    def _identify_iot_devices(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify IoT devices based on signatures"""
        iot_signatures = self.config.get('iot_signatures', {})
        mac_prefixes = iot_signatures.get('mac_prefixes', {})
        
        iot_devices = []
        
        for device in devices:
            mac = device.get('mac', '').upper()
            
            # Check MAC prefix
            for prefix, device_type in mac_prefixes.items():
                if mac.startswith(prefix.upper()):
                    device['iot_type'] = device_type
                    device['identification_method'] = 'MAC prefix'
                    iot_devices.append(device)
                    break
            
            # Check for common IoT ports and services
            open_ports = device.get('open_ports', [])
            services = device.get('services', [])
            
            # Common IoT indicators
            if any(port in [1900, 5000, 8080, 8443] for port in open_ports):
                for service in services:
                    service_name = service.get('service', '').lower()
                    product = service.get('product', '').lower()
                    
                    if any(keyword in f"{service_name} {product}" for keyword in 
                          ['upnp', 'iot', 'smart', 'thermostat', 'sensor']):
                        device['iot_type'] = 'Generic IoT Device'
                        device['identification_method'] = 'Service detection'
                        iot_devices.append(device)
                        break
        
        return iot_devices
    
    def _identify_printers(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify printers and get detailed information"""
        printers = []
        
        for device in devices:
            open_ports = device.get('open_ports', [])
            services = device.get('services', [])
            
            # Check for printer ports (IPP, LPD, JetDirect)
            printer_ports = [631, 515, 9100]
            if any(port in open_ports for port in printer_ports):
                printer_info = device.copy()
                printer_info['device_type'] = 'printer'
                
                # Try to get printer details via SNMP or HTTP
                printer_details = self._get_printer_details(device['ip'])
                printer_info.update(printer_details)
                
                printers.append(printer_info)
                continue
            
            # Check service signatures
            for service in services:
                service_name = service.get('service', '').lower()
                product = service.get('product', '').lower()
                
                if any(keyword in f"{service_name} {product}" for keyword in 
                      ['printer', 'cups', 'jetdirect', 'ipp']):
                    printer_info = device.copy()
                    printer_info['device_type'] = 'printer'
                    printer_info['printer_model'] = product
                    printers.append(printer_info)
                    break
        
        return printers
    
    def _identify_voip_phones(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify VoIP phones"""
        voip_phones = []
        
        for device in devices:
            open_ports = device.get('open_ports', [])
            services = device.get('services', [])
            
            # Check for SIP ports
            sip_ports = [5060, 5061]
            if any(port in open_ports for port in sip_ports):
                phone_info = device.copy()
                phone_info['device_type'] = 'voip_phone'
                voip_phones.append(phone_info)
                continue
            
            # Check service signatures
            for service in services:
                service_name = service.get('service', '').lower()
                product = service.get('product', '').lower()
                
                if any(keyword in f"{service_name} {product}" for keyword in 
                      ['sip', 'voip', 'phone', 'cisco', 'polycom', 'yealink']):
                    phone_info = device.copy()
                    phone_info['device_type'] = 'voip_phone'
                    phone_info['phone_model'] = product
                    voip_phones.append(phone_info)
                    break
        
        return voip_phones
    
    def _identify_cameras(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify IP cameras"""
        cameras = []
        
        for device in devices:
            services = device.get('services', [])
            
            for service in services:
                product = service.get('product', '').lower()
                extrainfo = service.get('extrainfo', '').lower()
                
                if any(keyword in f"{product} {extrainfo}" for keyword in 
                      ['camera', 'webcam', 'axis', 'hikvision', 'dahua']):
                    camera_info = device.copy()
                    camera_info['device_type'] = 'camera'
                    camera_info['camera_model'] = product
                    cameras.append(camera_info)
                    break
        
        return cameras
    
    def _get_printer_details(self, ip: str) -> Dict[str, Any]:
        """Get detailed printer information"""
        details = {}
        
        # Try SNMP queries for printer info
        try:
            # Common printer SNMP OIDs
            # This is a simplified version - full implementation would use pysnmp
            details['snmp_available'] = True
        except Exception:
            details['snmp_available'] = False
        
        # Try HTTP interface
        try:
            response = requests.get(f"http://{ip}", timeout=5)
            if response.status_code == 200:
                content = response.text.lower()
                if any(keyword in content for keyword in ['printer', 'toner', 'cartridge']):
                    details['web_interface'] = True
                    # Parse printer model from HTML if available
                    model_match = re.search(r'<title>([^<]*printer[^<]*)</title>', content, re.IGNORECASE)
                    if model_match:
                        details['printer_model'] = model_match.group(1).strip()
        except Exception:
            pass
        
        return details
    
    def _probe_http_services(self, host: str, open_ports: List[int]) -> Dict[str, Any]:
        """Probe HTTP services for additional device information"""
        http_info = {}
        
        http_ports = [80, 443, 8080, 8443]
        for port in http_ports:
            if port in open_ports:
                try:
                    protocol = 'https' if port in [443, 8443] else 'http'
                    url = f"{protocol}://{host}:{port}"
                    
                    response = requests.get(url, timeout=3, verify=False)
                    if response.status_code == 200:
                        http_info['web_interface'] = True
                        http_info['web_title'] = self._extract_title(response.text)
                        break
                except Exception:
                    continue
        
        return http_info
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        match = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else ""
    
    def _get_os_guess(self, host_info) -> str:
        """Get OS guess from nmap results"""
        try:
            if 'osmatch' in host_info:
                return host_info['osmatch'][0]['name']
        except (KeyError, IndexError):
            pass
        return "Unknown"
    
    def _get_vendor_from_mac(self, mac: str) -> str:
        """Get vendor from MAC address prefix"""
        if not mac or mac == "Unknown":
            return "Unknown"
        
        # This would typically use an OUI database
        # Simplified version with common prefixes
        oui_map = {
            "00:1B:21": "Cisco",
            "00:04:F2": "Polycom", 
            "00:0F:34": "Axis",
            "B8:27:EB": "Raspberry Pi Foundation",
            "DC:A6:32": "Raspberry Pi Foundation"
        }
        
        prefix = mac[:8].upper()
        return oui_map.get(prefix, "Unknown")