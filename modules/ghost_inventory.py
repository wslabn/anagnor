import nmap
import ldap
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
import re
from concurrent.futures import ThreadPoolExecutor
from utils.network_utils import NetworkUtils

class GhostInventoryScanner:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        
    def scan(self, networks: List[str]) -> Dict[str, Any]:
        """Scan for ghost inventory across networks"""
        results = {
            'domain_machines': [],
            'stale_assets': [],
            'shadow_it': [],
            'unmanaged_devices': []
        }
        
        # Get domain machines if configured
        domain_machines = self._get_domain_machines()
        results['domain_machines'] = domain_machines
        
        # Discover all network devices
        discovered_devices = []
        for network in networks:
            devices = self._discover_network_devices(network)
            discovered_devices.extend(devices)
            
        # Analyze devices for ghost inventory
        results['stale_assets'] = self._find_stale_assets(domain_machines)
        results['shadow_it'] = self._find_shadow_it(discovered_devices)
        results['unmanaged_devices'] = self._find_unmanaged_devices(discovered_devices, domain_machines)
        
        return results
    
    def _get_domain_machines(self) -> List[Dict[str, Any]]:
        """Query Active Directory for domain machines"""
        domain_config = self.config.get('domain', {})
        
        if not all([domain_config.get('server'), domain_config.get('username')]):
            self.logger.warning("Domain configuration incomplete, skipping AD query")
            return []
            
        try:
            ldap_server = f"ldap://{domain_config['server']}"
            conn = ldap.initialize(ldap_server)
            conn.simple_bind_s(domain_config['username'], domain_config['password'])
            
            search_filter = "(objectClass=computer)"
            attributes = ['cn', 'lastLogonTimestamp', 'operatingSystem', 'dNSHostName']
            
            result = conn.search_s(
                domain_config['base_dn'],
                ldap.SCOPE_SUBTREE,
                search_filter,
                attributes
            )
            
            machines = []
            for dn, attrs in result:
                machine = {
                    'name': attrs.get('cn', [b''])[0].decode('utf-8'),
                    'dns_name': attrs.get('dNSHostName', [b''])[0].decode('utf-8'),
                    'os': attrs.get('operatingSystem', [b''])[0].decode('utf-8'),
                    'last_logon': self._convert_ad_timestamp(attrs.get('lastLogonTimestamp', [b'0'])[0])
                }
                machines.append(machine)
                
            conn.unbind()
            return machines
            
        except Exception as e:
            self.logger.error(f"Failed to query domain: {e}")
            return []
    
    def _discover_network_devices(self, network: str) -> List[Dict[str, Any]]:
        """Discover devices on network using nmap"""
        self.logger.info(f"Scanning network: {network}")
        
        try:
            # Quick host discovery scan
            self.nm.scan(hosts=network, arguments='-sn')
            
            devices = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    hostname = NetworkUtils.resolve_hostname(host)
                    mac = NetworkUtils.get_mac_address(host)
                    
                    device = {
                        'ip': host,
                        'hostname': hostname,
                        'mac': mac,
                        'discovered_time': datetime.now().isoformat()
                    }
                    devices.append(device)
                    
            return devices
            
        except Exception as e:
            self.logger.error(f"Network scan failed for {network}: {e}")
            return []
    
    def _find_stale_assets(self, domain_machines: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find domain machines that haven't checked in recently"""
        stale_threshold = datetime.now() - timedelta(days=30)
        stale_assets = []
        
        for machine in domain_machines:
            last_logon = machine.get('last_logon')
            if last_logon and last_logon < stale_threshold:
                machine['days_stale'] = (datetime.now() - last_logon).days
                stale_assets.append(machine)
                
        return stale_assets
    
    def _find_shadow_it(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify devices that don't follow naming conventions"""
        corporate_patterns = self.config.get_list('naming_conventions.corporate_patterns')
        shadow_indicators = self.config.get_list('naming_conventions.shadow_indicators')
        
        shadow_devices = []
        
        for device in devices:
            hostname = device.get('hostname', '').lower()
            
            # Skip if matches corporate pattern
            is_corporate = False
            for pattern in corporate_patterns:
                if re.match(pattern, hostname, re.IGNORECASE):
                    is_corporate = True
                    break
                    
            if not is_corporate:
                # Check for shadow IT indicators
                for indicator in shadow_indicators:
                    if re.search(indicator, hostname, re.IGNORECASE):
                        device['shadow_reason'] = f"Matches pattern: {indicator}"
                        shadow_devices.append(device)
                        break
                        
        return shadow_devices
    
    def _find_unmanaged_devices(self, discovered_devices: List[Dict[str, Any]], 
                               domain_machines: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find devices not in domain but on network"""
        domain_names = {m.get('dns_name', '').lower() for m in domain_machines}
        domain_names.update({m.get('name', '').lower() for m in domain_machines})
        
        unmanaged = []
        for device in discovered_devices:
            hostname = device.get('hostname', '').lower()
            if hostname not in domain_names and hostname != device.get('ip'):
                unmanaged.append(device)
                
        return unmanaged
    
    def _convert_ad_timestamp(self, timestamp_bytes) -> datetime:
        """Convert Active Directory timestamp to datetime"""
        try:
            timestamp = int(timestamp_bytes.decode('utf-8'))
            # AD timestamp is 100-nanosecond intervals since Jan 1, 1601
            return datetime(1601, 1, 1) + timedelta(microseconds=timestamp/10)
        except (ValueError, AttributeError):
            return datetime.min