import nmap
import logging
import re
from typing import Dict, List, Any
import requests
from collections import defaultdict
from utils.network_utils import NetworkUtils

class SoftwareAuditScanner:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        
    def scan(self, networks: List[str]) -> Dict[str, Any]:
        """Audit software installations and versions"""
        results = {
            'missing_agents': [],
            'version_drift': {},
            'software_inventory': [],
            'license_compliance': []
        }
        
        # Scan networks for software information
        all_hosts = []
        for network in networks:
            hosts = self._scan_software_inventory(network)
            all_hosts.extend(hosts)
        
        # Analyze software findings
        results['missing_agents'] = self._find_missing_agents(all_hosts)
        results['version_drift'] = self._analyze_version_drift(all_hosts)
        results['software_inventory'] = all_hosts
        results['license_compliance'] = self._check_license_compliance(all_hosts)
        
        return results
    
    def _scan_software_inventory(self, network: str) -> List[Dict[str, Any]]:
        """Scan network for software inventory"""
        self.logger.info(f"Software inventory scan: {network}")
        
        try:
            # Scan common application ports
            app_ports = [80, 443, 8080, 8443, 3389, 5900, 22, 23]
            port_range = ','.join(map(str, app_ports))
            
            self.nm.scan(hosts=network, ports=port_range, 
                        arguments='-sS -sV --version-intensity 7')
            
            hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    host_info = self._analyze_host_software(host)
                    hosts.append(host_info)
                    
            return hosts
            
        except Exception as e:
            self.logger.error(f"Software scan failed for {network}: {e}")
            return []
    
    def _analyze_host_software(self, host: str) -> Dict[str, Any]:
        """Analyze software on individual host"""
        host_info = self.nm[host]
        
        device = {
            'ip': host,
            'hostname': NetworkUtils.resolve_hostname(host),
            'os_info': self._get_os_info(host_info),
            'detected_software': [],
            'web_applications': [],
            'security_software': [],
            'missing_agents': []
        }
        
        # Analyze services for software detection
        for protocol in host_info.all_protocols():
            ports = host_info[protocol].keys()
            for port in ports:
                port_info = host_info[protocol][port]
                if port_info['state'] == 'open':
                    software_info = self._extract_software_info(port, port_info)
                    if software_info:
                        device['detected_software'].append(software_info)
        
        # Probe web applications
        device['web_applications'] = self._probe_web_applications(host, device['detected_software'])
        
        # Check for security software
        device['security_software'] = self._detect_security_software(device['detected_software'])
        
        return device
    
    def _extract_software_info(self, port: int, port_info: Dict) -> Dict[str, Any]:
        """Extract software information from port scan"""
        software = {
            'port': port,
            'service': port_info.get('name', ''),
            'product': port_info.get('product', ''),
            'version': port_info.get('version', ''),
            'extrainfo': port_info.get('extrainfo', ''),
            'cpe': port_info.get('cpe', ''),
            'software_type': self._categorize_software(port_info)
        }
        
        return software if software['product'] else None
    
    def _categorize_software(self, port_info: Dict) -> str:
        """Categorize software type"""
        product = port_info.get('product', '').lower()
        service = port_info.get('name', '').lower()
        
        if any(web in product for web in ['apache', 'nginx', 'iis', 'tomcat']):
            return 'web_server'
        elif any(db in product for db in ['mysql', 'postgresql', 'mssql', 'oracle']):
            return 'database'
        elif any(sec in product for sec in ['antivirus', 'firewall', 'edr']):
            return 'security'
        elif 'ssh' in service or 'telnet' in service:
            return 'remote_access'
        elif any(app in product for app in ['office', 'adobe', 'chrome', 'firefox']):
            return 'application'
        else:
            return 'other'
    
    def _probe_web_applications(self, host: str, detected_software: List[Dict]) -> List[Dict[str, Any]]:
        """Probe web applications for detailed information"""
        web_apps = []
        
        # Find web servers
        web_ports = []
        for software in detected_software:
            if software.get('software_type') == 'web_server':
                web_ports.append(software['port'])
        
        # Add common web ports if not already detected
        for port in [80, 443, 8080, 8443]:
            if port not in web_ports:
                web_ports.append(port)
        
        for port in web_ports:
            try:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{host}:{port}"
                
                response = requests.get(url, timeout=5, verify=False, 
                                      headers={'User-Agent': 'Anagnor-Scanner'})
                
                if response.status_code == 200:
                    app_info = self._analyze_web_response(response, url)
                    if app_info:
                        web_apps.append(app_info)
                        
            except Exception:
                continue
        
        return web_apps
    
    def _analyze_web_response(self, response, url: str) -> Dict[str, Any]:
        """Analyze web response for application details"""
        headers = response.headers
        content = response.text
        
        app_info = {
            'url': url,
            'title': self._extract_title(content),
            'server': headers.get('Server', ''),
            'technologies': [],
            'cms': None,
            'frameworks': []
        }
        
        # Detect technologies from headers
        if 'X-Powered-By' in headers:
            app_info['technologies'].append(headers['X-Powered-By'])
        
        # Detect CMS and frameworks from content
        cms_patterns = {
            'WordPress': [r'wp-content', r'wordpress'],
            'Drupal': [r'drupal', r'sites/default'],
            'Joomla': [r'joomla', r'administrator'],
            'SharePoint': [r'sharepoint', r'_layouts']
        }
        
        for cms, patterns in cms_patterns.items():
            if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                app_info['cms'] = cms
                break
        
        # Detect JavaScript frameworks
        js_frameworks = {
            'jQuery': r'jquery',
            'Angular': r'angular',
            'React': r'react',
            'Vue.js': r'vue\.js'
        }
        
        for framework, pattern in js_frameworks.items():
            if re.search(pattern, content, re.IGNORECASE):
                app_info['frameworks'].append(framework)
        
        return app_info
    
    def _detect_security_software(self, detected_software: List[Dict]) -> List[Dict[str, Any]]:
        """Detect security software from service scans"""
        security_software = []
        
        security_indicators = {
            'Windows Defender': ['windows defender', 'msmpeng'],
            'Symantec': ['symantec', 'norton'],
            'McAfee': ['mcafee', 'mcshield'],
            'CrowdStrike': ['crowdstrike', 'falcon'],
            'Carbon Black': ['carbon black', 'cb'],
            'Sophos': ['sophos'],
            'Kaspersky': ['kaspersky'],
            'Trend Micro': ['trend micro', 'tmccsf']
        }
        
        for software in detected_software:
            product = software.get('product', '').lower()
            extrainfo = software.get('extrainfo', '').lower()
            combined = f"{product} {extrainfo}"
            
            for sec_product, indicators in security_indicators.items():
                if any(indicator in combined for indicator in indicators):
                    security_software.append({
                        'product': sec_product,
                        'version': software.get('version', 'Unknown'),
                        'port': software.get('port'),
                        'detection_method': 'service_scan'
                    })
                    break
        
        return security_software
    
    def _find_missing_agents(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find hosts missing required security agents"""
        required_agents = self.config.get_list('software_tracking.security')
        missing_agents = []
        
        for host in hosts:
            security_software = host.get('security_software', [])
            detected_products = [s.get('product', '').lower() for s in security_software]
            
            missing = []
            for required in required_agents:
                if not any(required.lower() in product for product in detected_products):
                    missing.append(required)
            
            if missing:
                host_info = {
                    'ip': host['ip'],
                    'hostname': host['hostname'],
                    'missing_agents': missing,
                    'detected_security': detected_products,
                    'risk_level': 'High' if len(missing) > 1 else 'Medium'
                }
                missing_agents.append(host_info)
        
        return missing_agents
    
    def _analyze_version_drift(self, hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze version drift across software installations"""
        software_versions = defaultdict(lambda: defaultdict(int))
        
        # Collect version information
        for host in hosts:
            for software in host.get('detected_software', []):
                product = software.get('product', '').lower()
                version = software.get('version', 'Unknown')
                
                if product and version != 'Unknown':
                    software_versions[product][version] += 1
        
        # Analyze drift
        version_drift = {}
        for product, versions in software_versions.items():
            if len(versions) > 1:  # Multiple versions detected
                total_installs = sum(versions.values())
                version_list = [
                    {
                        'version': version,
                        'count': count,
                        'percentage': round((count / total_installs) * 100, 1)
                    }
                    for version, count in sorted(versions.items(), key=lambda x: x[1], reverse=True)
                ]
                
                version_drift[product] = {
                    'total_installations': total_installs,
                    'unique_versions': len(versions),
                    'versions': version_list,
                    'drift_score': len(versions) / total_installs * 100  # Higher = more drift
                }
        
        return version_drift
    
    def _check_license_compliance(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for potential license compliance issues"""
        compliance_issues = []
        
        # Track commercial software installations
        commercial_software = {
            'microsoft office': 'Microsoft Office',
            'adobe': 'Adobe Products',
            'autocad': 'AutoCAD',
            'vmware': 'VMware Products'
        }
        
        software_counts = defaultdict(int)
        
        for host in hosts:
            for software in host.get('detected_software', []):
                product = software.get('product', '').lower()
                
                for commercial, display_name in commercial_software.items():
                    if commercial in product:
                        software_counts[display_name] += 1
                        break
        
        # Flag high installation counts for review
        for software, count in software_counts.items():
            if count > 10:  # Threshold for review
                compliance_issues.append({
                    'software': software,
                    'installation_count': count,
                    'recommendation': f'Review licensing for {count} installations of {software}'
                })
        
        return compliance_issues
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        match = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else ""
    
    def _get_os_info(self, host_info) -> Dict[str, str]:
        """Get OS information from scan results"""
        try:
            if 'osmatch' in host_info and host_info['osmatch']:
                return {
                    'name': host_info['osmatch'][0].get('name', 'Unknown'),
                    'accuracy': str(host_info['osmatch'][0].get('accuracy', 0))
                }
        except (KeyError, IndexError):
            pass
        return {'name': 'Unknown', 'accuracy': '0'}