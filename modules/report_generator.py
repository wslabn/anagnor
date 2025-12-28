import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from jinja2 import Template
import base64

class ReportGenerator:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def generate(self, results: Dict[str, Any], output_format: str = 'html') -> str:
        """Generate assessment report"""
        if output_format == 'html':
            return self._generate_html_report(results)
        elif output_format == 'json':
            return self._generate_json_report(results)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive HTML report"""
        template_str = self._get_html_template()
        template = Template(template_str)
        
        # Prepare data for template
        report_data = {
            'company_name': self.config.get('report.company_name', 'Network Assessment'),
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'results': results,
            'summary': results.get('summary', {}),
            'metadata': results.get('scan_metadata', {}),
            'risk_analysis': self._generate_risk_analysis(results),
            'recommendations': self._generate_recommendations(results),
            'charts_data': self._prepare_charts_data(results)
        }
        
        # Render template
        html_content = template.render(**report_data)
        
        # Save to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"anagnor_report_{timestamp}.html"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {filename}")
        return filename
    
    def _generate_json_report(self, results: Dict[str, Any]) -> str:
        """Generate JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"anagnor_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"JSON report generated: {filename}")
        return filename
    
    def _generate_risk_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk analysis summary"""
        analysis = {
            'overall_risk': 'Low',
            'critical_findings': [],
            'risk_categories': {},
            'immediate_actions': []
        }
        
        summary = results.get('summary', {})
        risk_score = summary.get('risk_score', 0)
        
        # Determine overall risk level
        if risk_score >= 80:
            analysis['overall_risk'] = 'Critical'
        elif risk_score >= 60:
            analysis['overall_risk'] = 'High'
        elif risk_score >= 40:
            analysis['overall_risk'] = 'Medium'
        else:
            analysis['overall_risk'] = 'Low'
        
        # Analyze critical findings
        risk_data = results.get('risk_discovery', {})
        
        # EOL Systems
        eol_systems = risk_data.get('eol_systems', [])
        if eol_systems:
            analysis['critical_findings'].append({
                'type': 'End-of-Life Systems',
                'count': len(eol_systems),
                'severity': 'Critical',
                'description': f'{len(eol_systems)} systems running unsupported operating systems'
            })
            analysis['immediate_actions'].append('Upgrade or isolate End-of-Life systems immediately')
        
        # Open Risk Ports
        risk_ports = risk_data.get('open_risk_ports', [])
        if risk_ports:
            analysis['critical_findings'].append({
                'type': 'Open Risk Ports',
                'count': len(risk_ports),
                'severity': 'High',
                'description': f'{len(risk_ports)} systems with dangerous ports exposed'
            })
            analysis['immediate_actions'].append('Close unnecessary SMB and RDP ports')
        
        # Ghost Assets
        ghost_data = results.get('ghost_inventory', {})
        stale_assets = ghost_data.get('stale_assets', [])
        if stale_assets:
            analysis['critical_findings'].append({
                'type': 'Stale Assets',
                'count': len(stale_assets),
                'severity': 'Medium',
                'description': f'{len(stale_assets)} domain machines inactive for 30+ days'
            })
        
        # Missing Security Agents
        software_data = results.get('software_audit', {})
        missing_agents = software_data.get('missing_agents', [])
        if missing_agents:
            analysis['critical_findings'].append({
                'type': 'Missing Security Agents',
                'count': len(missing_agents),
                'severity': 'High',
                'description': f'{len(missing_agents)} systems missing required security software'
            })
            analysis['immediate_actions'].append('Deploy security agents to unprotected systems')
        
        return analysis
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # High Priority Recommendations
        risk_data = results.get('risk_discovery', {})
        
        if risk_data.get('eol_systems'):
            recommendations.append({
                'priority': 'Critical',
                'category': 'Security',
                'title': 'Upgrade End-of-Life Systems',
                'description': 'Systems running unsupported operating systems pose critical security risks',
                'action': 'Plan immediate upgrades or network isolation for EOL systems',
                'timeline': 'Immediate (1-2 weeks)'
            })
        
        if risk_data.get('open_risk_ports'):
            recommendations.append({
                'priority': 'High',
                'category': 'Network Security',
                'title': 'Close Dangerous Ports',
                'description': 'SMB and RDP ports are common ransomware attack vectors',
                'action': 'Implement firewall rules to restrict access to ports 445 and 3389',
                'timeline': 'Immediate (1 week)'
            })
        
        # Medium Priority Recommendations
        ghost_data = results.get('ghost_inventory', {})
        
        if ghost_data.get('stale_assets'):
            recommendations.append({
                'priority': 'Medium',
                'category': 'Asset Management',
                'title': 'Clean Up Stale Assets',
                'description': 'Inactive domain machines create security and licensing risks',
                'action': 'Review and remove inactive computer accounts from Active Directory',
                'timeline': 'Short-term (2-4 weeks)'
            })
        
        if ghost_data.get('shadow_it'):
            recommendations.append({
                'priority': 'Medium',
                'category': 'Governance',
                'title': 'Address Shadow IT',
                'description': 'Unmanaged devices bypass security controls',
                'action': 'Implement device registration and compliance policies',
                'timeline': 'Medium-term (1-2 months)'
            })
        
        # IoT and Device Management
        dark_data = results.get('dark_hardware', {})
        
        if dark_data.get('iot_devices'):
            recommendations.append({
                'priority': 'Medium',
                'category': 'IoT Security',
                'title': 'Secure IoT Devices',
                'description': 'IoT devices often have weak security and default credentials',
                'action': 'Inventory, update firmware, and segment IoT devices on separate network',
                'timeline': 'Medium-term (1-3 months)'
            })
        
        # Software Management
        software_data = results.get('software_audit', {})
        
        if software_data.get('version_drift'):
            recommendations.append({
                'priority': 'Low',
                'category': 'Patch Management',
                'title': 'Standardize Software Versions',
                'description': 'Version drift complicates security patching and support',
                'action': 'Implement centralized software deployment and patch management',
                'timeline': 'Long-term (3-6 months)'
            })
        
        return recommendations
    
    def _prepare_charts_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for charts and visualizations"""
        charts = {}
        
        # Risk Score Gauge
        summary = results.get('summary', {})
        charts['risk_gauge'] = {
            'score': summary.get('risk_score', 0),
            'max_score': 100
        }
        
        # Device Type Distribution
        dark_data = results.get('dark_hardware', {})
        device_counts = {
            'Computers': summary.get('total_devices', 0) - len(dark_data.get('iot_devices', [])),
            'IoT Devices': len(dark_data.get('iot_devices', [])),
            'Printers': len(dark_data.get('printers', [])),
            'VoIP Phones': len(dark_data.get('voip_phones', [])),
            'Cameras': len(dark_data.get('cameras', []))
        }
        charts['device_distribution'] = device_counts
        
        # Risk Categories
        risk_categories = {
            'EOL Systems': len(results.get('risk_discovery', {}).get('eol_systems', [])),
            'Open Risk Ports': len(results.get('risk_discovery', {}).get('open_risk_ports', [])),
            'Stale Assets': len(results.get('ghost_inventory', {}).get('stale_assets', [])),
            'Missing Agents': len(results.get('software_audit', {}).get('missing_agents', []))
        }
        charts['risk_categories'] = risk_categories
        
        # Version Drift Analysis
        version_drift = results.get('software_audit', {}).get('version_drift', {})
        charts['version_drift'] = [
            {
                'software': software,
                'versions': data['unique_versions'],
                'installations': data['total_installations']
            }
            for software, data in version_drift.items()
        ]
        
        return charts
    
    def _get_html_template(self) -> str:
        """Get HTML template for report"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ company_name }} - Network Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; margin: 0; font-size: 2.5em; }
        .header p { color: #7f8c8d; margin: 10px 0 0 0; font-size: 1.1em; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: linear-gradient(135deg, #3498db, #2980b9); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card.critical { background: linear-gradient(135deg, #e74c3c, #c0392b); }
        .summary-card.warning { background: linear-gradient(135deg, #f39c12, #e67e22); }
        .summary-card.success { background: linear-gradient(135deg, #27ae60, #229954); }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 2em; }
        .summary-card p { margin: 0; opacity: 0.9; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
        .risk-level { padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; display: inline-block; }
        .risk-critical { background: #e74c3c; }
        .risk-high { background: #f39c12; }
        .risk-medium { background: #f1c40f; color: #2c3e50; }
        .risk-low { background: #27ae60; }
        .findings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .finding-card { border: 1px solid #ecf0f1; border-radius: 8px; padding: 20px; background: white; }
        .finding-card h4 { margin: 0 0 10px 0; color: #2c3e50; }
        .recommendations { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #3498db; }
        .recommendation { margin-bottom: 15px; padding: 15px; background: white; border-radius: 5px; border-left: 3px solid #3498db; }
        .recommendation.critical { border-left-color: #e74c3c; }
        .recommendation.high { border-left-color: #f39c12; }
        .recommendation.medium { border-left-color: #f1c40f; }
        .table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }
        .table th { background: #f8f9fa; font-weight: bold; color: #2c3e50; }
        .table tr:hover { background: #f8f9fa; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ecf0f1; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ company_name }}</h1>
            <p>Network Security Assessment Report</p>
            <p>Generated on {{ scan_date }}</p>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>{{ summary.total_devices }}</h3>
                    <p>Total Devices</p>
                </div>
                <div class="summary-card {% if summary.critical_risks > 0 %}critical{% elif summary.critical_risks == 0 %}success{% endif %}">
                    <h3>{{ summary.critical_risks }}</h3>
                    <p>Critical Risks</p>
                </div>
                <div class="summary-card {% if summary.ghost_assets > 5 %}warning{% elif summary.ghost_assets == 0 %}success{% endif %}">
                    <h3>{{ summary.ghost_assets }}</h3>
                    <p>Ghost Assets</p>
                </div>
                <div class="summary-card {% if summary.eol_systems > 0 %}critical{% else %}success{% endif %}">
                    <h3>{{ summary.eol_systems }}</h3>
                    <p>EOL Systems</p>
                </div>
            </div>
            
            <div style="text-align: center; margin: 20px 0;">
                <h3>Overall Risk Score: 
                    <span class="risk-level {% if summary.risk_score >= 80 %}risk-critical{% elif summary.risk_score >= 60 %}risk-high{% elif summary.risk_score >= 40 %}risk-medium{% else %}risk-low{% endif %}">
                        {{ summary.risk_score }}/100
                    </span>
                </h3>
            </div>
        </div>

        <!-- Risk Analysis -->
        <div class="section">
            <h2>Risk Analysis</h2>
            <div class="findings-grid">
                {% for finding in risk_analysis.critical_findings %}
                <div class="finding-card">
                    <h4>{{ finding.type }}</h4>
                    <p><span class="risk-level risk-{{ finding.severity.lower() }}">{{ finding.severity }}</span></p>
                    <p>{{ finding.description }}</p>
                    <p><strong>Count:</strong> {{ finding.count }}</p>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- Ghost Inventory -->
        {% if results.ghost_inventory %}
        <div class="section">
            <h2>Ghost Inventory Findings</h2>
            
            {% if results.ghost_inventory.stale_assets %}
            <h3>Stale Assets ({{ results.ghost_inventory.stale_assets|length }})</h3>
            <table class="table">
                <thead>
                    <tr><th>Computer Name</th><th>DNS Name</th><th>Operating System</th><th>Days Stale</th></tr>
                </thead>
                <tbody>
                    {% for asset in results.ghost_inventory.stale_assets[:10] %}
                    <tr>
                        <td>{{ asset.name }}</td>
                        <td>{{ asset.dns_name }}</td>
                        <td>{{ asset.os }}</td>
                        <td>{{ asset.days_stale }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}

            {% if results.ghost_inventory.shadow_it %}
            <h3>Shadow IT Devices ({{ results.ghost_inventory.shadow_it|length }})</h3>
            <table class="table">
                <thead>
                    <tr><th>IP Address</th><th>Hostname</th><th>MAC Address</th><th>Reason</th></tr>
                </thead>
                <tbody>
                    {% for device in results.ghost_inventory.shadow_it[:10] %}
                    <tr>
                        <td>{{ device.ip }}</td>
                        <td>{{ device.hostname }}</td>
                        <td>{{ device.mac }}</td>
                        <td>{{ device.shadow_reason }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
        </div>
        {% endif %}

        <!-- Dark Hardware -->
        {% if results.dark_hardware %}
        <div class="section">
            <h2>Dark Hardware Findings</h2>
            
            {% if results.dark_hardware.iot_devices %}
            <h3>IoT Devices ({{ results.dark_hardware.iot_devices|length }})</h3>
            <table class="table">
                <thead>
                    <tr><th>IP Address</th><th>Hostname</th><th>Device Type</th><th>Vendor</th></tr>
                </thead>
                <tbody>
                    {% for device in results.dark_hardware.iot_devices[:10] %}
                    <tr>
                        <td>{{ device.ip }}</td>
                        <td>{{ device.hostname }}</td>
                        <td>{{ device.iot_type }}</td>
                        <td>{{ device.vendor }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}

            {% if results.dark_hardware.printers %}
            <h3>Printers ({{ results.dark_hardware.printers|length }})</h3>
            <table class="table">
                <thead>
                    <tr><th>IP Address</th><th>Hostname</th><th>Model</th><th>Web Interface</th></tr>
                </thead>
                <tbody>
                    {% for printer in results.dark_hardware.printers[:10] %}
                    <tr>
                        <td>{{ printer.ip }}</td>
                        <td>{{ printer.hostname }}</td>
                        <td>{{ printer.get('printer_model', 'Unknown') }}</td>
                        <td>{{ 'Yes' if printer.get('web_interface') else 'No' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
        </div>
        {% endif %}

        <!-- Critical Risks -->
        {% if results.risk_discovery %}
        <div class="section">
            <h2>Critical Risk Discovery</h2>
            
            {% if results.risk_discovery.eol_systems %}
            <h3>End-of-Life Systems ({{ results.risk_discovery.eol_systems|length }})</h3>
            <table class="table">
                <thead>
                    <tr><th>IP Address</th><th>Hostname</th><th>EOL Operating System</th><th>Risk Level</th></tr>
                </thead>
                <tbody>
                    {% for system in results.risk_discovery.eol_systems[:10] %}
                    <tr>
                        <td>{{ system.ip }}</td>
                        <td>{{ system.hostname }}</td>
                        <td>{{ system.eol_os }}</td>
                        <td><span class="risk-level risk-{{ system.risk_level.lower() }}">{{ system.risk_level }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}

            {% if results.risk_discovery.open_risk_ports %}
            <h3>Open Risk Ports ({{ results.risk_discovery.open_risk_ports|length }})</h3>
            <table class="table">
                <thead>
                    <tr><th>IP Address</th><th>Hostname</th><th>Risk Ports</th><th>Total Risk Ports</th></tr>
                </thead>
                <tbody>
                    {% for host in results.risk_discovery.open_risk_ports[:10] %}
                    <tr>
                        <td>{{ host.ip }}</td>
                        <td>{{ host.hostname }}</td>
                        <td>
                            {% for port in host.risk_ports %}
                            <span class="risk-level risk-{{ port.risk_level.lower() }}">{{ port.port }} ({{ port.service }})</span>
                            {% endfor %}
                        </td>
                        <td>{{ host.total_risk_ports }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
        </div>
        {% endif %}

        <!-- Recommendations -->
        <div class="section">
            <h2>Recommendations</h2>
            <div class="recommendations">
                {% for rec in recommendations %}
                <div class="recommendation {{ rec.priority.lower() }}">
                    <h4>{{ rec.title }} <span class="risk-level risk-{{ rec.priority.lower() }}">{{ rec.priority }}</span></h4>
                    <p><strong>Category:</strong> {{ rec.category }}</p>
                    <p><strong>Description:</strong> {{ rec.description }}</p>
                    <p><strong>Action:</strong> {{ rec.action }}</p>
                    <p><strong>Timeline:</strong> {{ rec.timeline }}</p>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- Scan Metadata -->
        <div class="section">
            <h2>Scan Information</h2>
            <table class="table">
                <tr><th>Start Time</th><td>{{ metadata.start_time }}</td></tr>
                <tr><th>End Time</th><td>{{ metadata.end_time }}</td></tr>
                <tr><th>Duration</th><td>{{ metadata.duration }}</td></tr>
                <tr><th>Networks Scanned</th><td>{{ metadata.target_networks|join(', ') }}</td></tr>
            </table>
        </div>

        <div class="footer">
            <p>Report generated by Anagnor Network Assessment Tool</p>
            <p>For questions or support, contact your IT security team</p>
        </div>
    </div>
</body>
</html>
        '''