#!/usr/bin/env python3
"""
Anagnor Usage Example
Simple script demonstrating how to use the Anagnor network assessment tool
"""

from anagnor import AnagnorScanner
import json

def main():
    print("Anagnor Network Assessment Tool - Example Usage")
    print("=" * 50)
    
    # Initialize scanner with default config
    scanner = AnagnorScanner('config.yaml')
    
    # Option 1: Auto-discover networks and scan
    print("Starting network assessment...")
    results = scanner.run_scan()
    
    # Option 2: Scan specific networks
    # results = scanner.run_scan(['192.168.1.0/24', '10.0.0.0/24'])
    
    # Display summary
    summary = results.get('summary', {})
    print(f"\nScan Complete!")
    print(f"Total Devices Found: {summary.get('total_devices', 0)}")
    print(f"Ghost Assets: {summary.get('ghost_assets', 0)}")
    print(f"IoT Devices: {summary.get('iot_devices', 0)}")
    print(f"Critical Risks: {summary.get('critical_risks', 0)}")
    print(f"EOL Systems: {summary.get('eol_systems', 0)}")
    print(f"Risk Score: {summary.get('risk_score', 0)}/100")
    
    # Generate HTML report
    report_file = scanner.generate_report('html')
    print(f"\nDetailed report generated: {report_file}")
    
    # Save raw results
    results_file = scanner.save_results()
    print(f"Raw results saved: {results_file}")
    
    # Display some key findings
    print("\n" + "="*50)
    print("KEY FINDINGS SUMMARY")
    print("="*50)
    
    # Ghost Inventory
    ghost_data = results.get('ghost_inventory', {})
    stale_assets = ghost_data.get('stale_assets', [])
    if stale_assets:
        print(f"\n🔍 GHOST INVENTORY:")
        print(f"   • {len(stale_assets)} stale domain assets found")
        for asset in stale_assets[:3]:  # Show first 3
            print(f"     - {asset.get('name', 'Unknown')} ({asset.get('days_stale', 0)} days stale)")
    
    # Shadow IT
    shadow_it = ghost_data.get('shadow_it', [])
    if shadow_it:
        print(f"   • {len(shadow_it)} shadow IT devices detected")
        for device in shadow_it[:3]:
            print(f"     - {device.get('hostname', device.get('ip', 'Unknown'))}")
    
    # Dark Hardware
    dark_data = results.get('dark_hardware', {})
    iot_devices = dark_data.get('iot_devices', [])
    if iot_devices:
        print(f"\n🌐 DARK HARDWARE:")
        print(f"   • {len(iot_devices)} IoT devices discovered")
        for device in iot_devices[:3]:
            print(f"     - {device.get('iot_type', 'Unknown IoT')} at {device.get('ip', 'Unknown IP')}")
    
    printers = dark_data.get('printers', [])
    if printers:
        print(f"   • {len(printers)} printers found")
        for printer in printers[:3]:
            print(f"     - {printer.get('hostname', printer.get('ip', 'Unknown'))} ({printer.get('printer_model', 'Unknown model')})")
    
    # Critical Risks
    risk_data = results.get('risk_discovery', {})
    eol_systems = risk_data.get('eol_systems', [])
    if eol_systems:
        print(f"\n⚠️  CRITICAL RISKS:")
        print(f"   • {len(eol_systems)} End-of-Life systems found")
        for system in eol_systems[:3]:
            print(f"     - {system.get('hostname', system.get('ip', 'Unknown'))} running {system.get('eol_os', 'Unknown OS')}")
    
    risk_ports = risk_data.get('open_risk_ports', [])
    if risk_ports:
        print(f"   • {len(risk_ports)} systems with dangerous ports open")
        for host in risk_ports[:3]:
            ports = [str(p['port']) for p in host.get('risk_ports', [])]
            print(f"     - {host.get('hostname', host.get('ip', 'Unknown'))}: ports {', '.join(ports)}")
    
    # Software Issues
    software_data = results.get('software_audit', {})
    missing_agents = software_data.get('missing_agents', [])
    if missing_agents:
        print(f"\n💻 SOFTWARE ISSUES:")
        print(f"   • {len(missing_agents)} systems missing security agents")
        for host in missing_agents[:3]:
            agents = ', '.join(host.get('missing_agents', []))
            print(f"     - {host.get('hostname', host.get('ip', 'Unknown'))}: missing {agents}")
    
    print(f"\n📊 Open the HTML report for detailed analysis: {report_file}")

if __name__ == "__main__":
    main()