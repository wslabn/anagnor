import nmap
import logging
import re
from typing import Dict, List, Any
from datetime import datetime
import socket
import subprocess
from utils.network_utils import NetworkUtils

class RiskDiscoveryScanner:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        
        # EOL OS signatures
        self.eol_signatures = {
            'Windows 7': ['windows 7', 'win 7'],
            'Windows 8': ['windows 8', 'win 8'],
            'Windows XP': ['windows xp', 'win xp'],
            'Windows Server 2003': ['server 2003', '2003'],
            'Windows Server 2008': ['server 2008', '2008'],
            'Ubuntu 14.04': ['ubuntu 14.04', '14.04'],
            'CentOS 6': ['centos 6', 'centos linux 6'],
            'Red Hat 6': ['red hat 6', 'rhel 6']
        }
        
    def scan(self, networks: List[str]) -> Dict[str, Any]:
        """Scan for critical security risks"""
        results = {
            'eol_systems': [],
            'open_risk_ports': [],
            'dual_homed': [],
            'vulnerable_services': []
        }
        
        # Scan each network for risks
        all_hosts = []
        for network in networks:
            hosts = self._scan_network_risks(network)
            all_hosts.extend(hosts)
        
        # Analyze findings
        results['eol_systems'] = self._identify_eol_systems(all_hosts)
        results['open_risk_ports'] = self._find_open_risk_ports(all_hosts)
        results['dual_homed'] = self._find_dual_homed_machines(all_hosts)
        results['vulnerable_services'] = self._identify_vulnerable_services(all_hosts)
        
        return results
    
    def _scan_network_risks(self, network: str) -> List[Dict[str, Any]]:
        """Scan network for security risks"""
        self.logger.info(f"Risk scanning network: {network}")
        
        try:
            # Scan for risk ports specifically
            risk_ports = self.config.get_list('port_scan.risk_ports')
            port_range = ','.join(map(str, risk_ports))
            
            # Aggressive scan for OS detection and service versions
            self.nm.scan(hosts=network, ports=port_range, 
                        arguments='-sS -O -sV --version-intensity 5')
            
            hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    host_info = self._analyze_host_risks(host)
                    hosts.append(host_info)
                    
            return hosts
            
        except Exception as e:
            self.logger.error(f"Risk scan failed for {network}: {e}")
            return []
    
    def _analyze_host_risks(self, host: str) -> Dict[str, Any]:
        """Analyze individual host for security risks"""
        host_info = self.nm[host]
        
        device = {
            'ip': host,
            'hostname': NetworkUtils.resolve_hostname(host),
            'mac': NetworkUtils.get_mac_address(host),
            'os_info': self._get_detailed_os_info(host_info),
            'open_ports': [],
            'services': [],
            'risk_score': 0,
            'vulnerabilities': []
        }
        
        # Analyze ports and services
        for protocol in host_info.all_protocols():
            ports = host_info[protocol].keys()
            for port in ports:
                port_info = host_info[protocol][port]
                if port_info['state'] == 'open':
                    device['open_ports'].append(port)
                    
                    service = {
                        'port': port,
                        'service': port_info.get('name', ''),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'cpe': port_info.get('cpe', '')
                    }
                    device['services'].append(service)
        
        # Check for network interfaces (dual-homed detection)
        device['interfaces'] = self._check_network_interfaces(host)
        
        return device
    
    def _identify_eol_systems(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify End-of-Life operating systems"""
        eol_systems = []
        
        for host in hosts:
            os_info = host.get('os_info', {})
            os_name = os_info.get('name', '').lower()
            
            for eol_os, signatures in self.eol_signatures.items():
                if any(sig in os_name for sig in signatures):
                    eol_host = host.copy()
                    eol_host['eol_os'] = eol_os
                    eol_host['risk_level'] = 'Critical'
                    eol_host['risk_reason'] = f"Running {eol_os} which is End-of-Life"
                    eol_systems.append(eol_host)
                    break
        
        return eol_systems
    
    def _find_open_risk_ports(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find hosts with dangerous ports open"""
        risk_ports = {
            445: {'name': 'SMB', 'risk': 'High', 'reason': 'Ransomware vector'},
            3389: {'name': 'RDP', 'risk': 'High', 'reason': 'Brute force target'},
            135: {'name': 'RPC', 'risk': 'Medium', 'reason': 'Information disclosure'},
            139: {'name': 'NetBIOS', 'risk': 'Medium', 'reason': 'Legacy protocol'},
            23: {'name': 'Telnet', 'risk': 'High', 'reason': 'Unencrypted protocol'},
            21: {'name': 'FTP', 'risk': 'Medium', 'reason': 'Unencrypted protocol'}
        }
        
        risky_hosts = []
        
        for host in hosts:
            open_ports = host.get('open_ports', [])
            host_risks = []
            
            for port in open_ports:
                if port in risk_ports:
                    risk_info = risk_ports[port]
                    host_risks.append({
                        'port': port,
                        'service': risk_info['name'],
                        'risk_level': risk_info['risk'],
                        'reason': risk_info['reason']
                    })
            
            if host_risks:
                risky_host = host.copy()
                risky_host['risk_ports'] = host_risks
                risky_host['total_risk_ports'] = len(host_risks)
                risky_hosts.append(risky_host)
        
        return risky_hosts
    
    def _find_dual_homed_machines(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find machines connected to multiple networks"""
        dual_homed = []
        
        for host in hosts:
            interfaces = host.get('interfaces', [])
            
            # Check if host has multiple active interfaces
            if len(interfaces) > 1:
                # Filter out loopback and virtual interfaces
                real_interfaces = [
                    iface for iface in interfaces 
                    if not iface.get('name', '').startswith(('lo', 'vir', 'docker'))
                ]
                
                if len(real_interfaces) > 1:
                    dual_host = host.copy()
                    dual_host['interface_count'] = len(real_interfaces)
                    dual_host['interfaces'] = real_interfaces
                    dual_host['risk_level'] = 'High'
                    dual_host['risk_reason'] = 'Multiple network connections create security bridge'
                    dual_homed.append(dual_host)
        
        return dual_homed
    
    def _identify_vulnerable_services(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify services with known vulnerabilities"""
        vulnerable_hosts = []
        
        # Known vulnerable service patterns
        vulnerable_patterns = {
            'apache': {
                'versions': ['2.2', '2.0'],
                'risk': 'Medium',
                'reason': 'Outdated Apache version'
            },
            'openssh': {
                'versions': ['5.', '6.0', '6.1', '6.2'],
                'risk': 'Medium', 
                'reason': 'Outdated SSH version'
            },
            'microsoft-iis': {
                'versions': ['6.0', '7.0'],
                'risk': 'High',
                'reason': 'Outdated IIS version'
            }
        }
        
        for host in hosts:
            services = host.get('services', [])
            vulnerabilities = []
            
            for service in services:
                product = service.get('product', '').lower()
                version = service.get('version', '')
                
                for vuln_service, vuln_info in vulnerable_patterns.items():
                    if vuln_service in product:
                        for vuln_version in vuln_info['versions']:
                            if vuln_version in version:
                                vulnerabilities.append({
                                    'service': product,
                                    'version': version,
                                    'port': service.get('port'),
                                    'risk_level': vuln_info['risk'],
                                    'reason': vuln_info['reason']
                                })
                                break
            
            if vulnerabilities:
                vuln_host = host.copy()
                vuln_host['vulnerabilities'] = vulnerabilities
                vuln_host['vulnerability_count'] = len(vulnerabilities)
                vulnerable_hosts.append(vuln_host)
        
        return vulnerable_hosts
    
    def _get_detailed_os_info(self, host_info) -> Dict[str, Any]:
        """Extract detailed OS information"""
        os_info = {'name': 'Unknown', 'accuracy': 0, 'family': 'Unknown'}
        
        try:
            if 'osmatch' in host_info and host_info['osmatch']:
                best_match = host_info['osmatch'][0]
                os_info['name'] = best_match.get('name', 'Unknown')
                os_info['accuracy'] = int(best_match.get('accuracy', 0))
                
                # Determine OS family
                name_lower = os_info['name'].lower()
                if 'windows' in name_lower:
                    os_info['family'] = 'Windows'
                elif any(linux in name_lower for linux in ['linux', 'ubuntu', 'centos', 'red hat']):
                    os_info['family'] = 'Linux'
                elif 'mac' in name_lower or 'darwin' in name_lower:
                    os_info['family'] = 'macOS'
                    
        except (KeyError, IndexError, ValueError):
            pass
            
        return os_info
    
    def _check_network_interfaces(self, host: str) -> List[Dict[str, Any]]:
        """Check network interfaces on host (simplified)"""
        # This is a simplified implementation
        # Full implementation would require agent deployment or SNMP
        interfaces = []
        
        try:
            # Try to get interface info via SNMP or other methods
            # For now, return basic info
            interfaces.append({
                'name': 'eth0',
                'ip': host,
                'status': 'up'
            })
        except Exception:
            pass
            
        return interfaces