#!/usr/bin/env python3
"""
Anagnor - Network Assessment Tool
Discovers ghost inventory, dark hardware, and critical risks in enterprise networks
"""

import json
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.ghost_inventory import GhostInventoryScanner
from modules.dark_hardware import DarkHardwareScanner
from modules.risk_discovery import RiskDiscoveryScanner
from modules.software_audit import SoftwareAuditScanner
from modules.report_generator import ReportGenerator
from utils.network_utils import NetworkUtils
from utils.config import Config

class AnagnorScanner:
    def __init__(self, config_path: str = "config.yaml"):
        self.config = Config(config_path)
        self.setup_logging()
        self.results = {}
        self.start_time = datetime.now()
        
        # Initialize scanners
        self.scanners = {
            'ghost_inventory': GhostInventoryScanner(self.config),
            'dark_hardware': DarkHardwareScanner(self.config),
            'risk_discovery': RiskDiscoveryScanner(self.config),
            'software_audit': SoftwareAuditScanner(self.config)
        }
        
    def setup_logging(self):
        logging.basicConfig(
            level=getattr(logging, self.config.get('log_level', 'INFO')),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('anagnor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def discover_network_ranges(self) -> List[str]:
        """Auto-discover network ranges to scan"""
        network_utils = NetworkUtils()
        ranges = network_utils.get_local_networks()
        
        # Add configured additional ranges
        additional_ranges = self.config.get('additional_networks', [])
        ranges.extend(additional_ranges)
        
        self.logger.info(f"Discovered network ranges: {ranges}")
        return ranges
        
    def run_scan(self, target_networks: List[str] = None) -> Dict[str, Any]:
        """Execute complete network assessment"""
        self.logger.info("Starting Anagnor network assessment")
        
        if not target_networks:
            target_networks = self.discover_network_ranges()
            
        # Run all scanners in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_scanner = {
                executor.submit(scanner.scan, target_networks): name
                for name, scanner in self.scanners.items()
            }
            
            for future in as_completed(future_to_scanner):
                scanner_name = future_to_scanner[future]
                try:
                    result = future.result()
                    self.results[scanner_name] = result
                    self.logger.info(f"Completed {scanner_name} scan")
                except Exception as e:
                    self.logger.error(f"Scanner {scanner_name} failed: {e}")
                    self.results[scanner_name] = {'error': str(e)}
        
        # Generate summary statistics
        self.results['summary'] = self._generate_summary()
        self.results['scan_metadata'] = {
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration': str(datetime.now() - self.start_time),
            'target_networks': target_networks
        }
        
        return self.results
        
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate high-level summary of findings"""
        summary = {
            'total_devices': 0,
            'critical_risks': 0,
            'ghost_assets': 0,
            'iot_devices': 0,
            'eol_systems': 0,
            'risk_score': 0
        }
        
        # Count findings from each scanner
        if 'ghost_inventory' in self.results:
            ghost_data = self.results['ghost_inventory']
            summary['ghost_assets'] = len(ghost_data.get('stale_assets', []))
            summary['total_devices'] += len(ghost_data.get('domain_machines', []))
            
        if 'dark_hardware' in self.results:
            dark_data = self.results['dark_hardware']
            summary['iot_devices'] = len(dark_data.get('iot_devices', []))
            summary['total_devices'] += len(dark_data.get('discovered_devices', []))
            
        if 'risk_discovery' in self.results:
            risk_data = self.results['risk_discovery']
            summary['eol_systems'] = len(risk_data.get('eol_systems', []))
            summary['critical_risks'] = len(risk_data.get('open_risk_ports', []))
            
        # Calculate risk score (0-100)
        risk_factors = [
            summary['ghost_assets'] * 2,
            summary['critical_risks'] * 10,
            summary['eol_systems'] * 5,
            len(self.results.get('risk_discovery', {}).get('dual_homed', [])) * 8
        ]
        summary['risk_score'] = min(100, sum(risk_factors))
        
        return summary
        
    def generate_report(self, output_format: str = 'html') -> str:
        """Generate assessment report"""
        generator = ReportGenerator(self.config)
        return generator.generate(self.results, output_format)
        
    def save_results(self, filename: str = None):
        """Save scan results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"anagnor_results_{timestamp}.json"
            
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
            
        self.logger.info(f"Results saved to {filename}")
        return filename

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Anagnor Network Assessment Tool')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    parser.add_argument('--networks', nargs='+', help='Target network ranges (e.g., 192.168.1.0/24)')
    parser.add_argument('--output', choices=['html', 'json', 'pdf'], default='html', help='Report format')
    parser.add_argument('--save', help='Save results to file')
    
    args = parser.parse_args()
    
    scanner = AnagnorScanner(args.config)
    results = scanner.run_scan(args.networks)
    
    # Generate report
    report_file = scanner.generate_report(args.output)
    print(f"Assessment complete. Report generated: {report_file}")
    
    # Save raw results if requested
    if args.save:
        scanner.save_results(args.save)

if __name__ == "__main__":
    main()