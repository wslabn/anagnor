# Anagnor - Network Assessment Tool

Anagnor is a comprehensive network assessment tool designed to discover and analyze enterprise networks, identifying security risks, ghost inventory, and dark hardware that traditional tools often miss.

## Features

### 🔍 Ghost Inventory Discovery
- **Stale Assets**: Identify domain machines inactive for 30+ days
- **Shadow IT**: Detect devices not following corporate naming conventions
- **Unmanaged Devices**: Find network devices not in Active Directory

### 🌐 Dark Hardware Detection
- **IoT Devices**: Smart thermostats, badge readers, IP cameras
- **Printer Audit**: Complete printer inventory with models and capabilities
- **VoIP Phones**: Separate phone network topology analysis
- **Industrial Equipment**: Identify unmanaged switches and hubs

### ⚠️ Critical Risk Assessment
- **End-of-Life Systems**: Flag Windows 7/8, outdated Linux systems
- **Open Risk Ports**: Identify SMB (445) and RDP (3389) exposure
- **Dual-Homed Machines**: Find systems bridging network segments
- **Vulnerable Services**: Detect outdated software versions

### 💻 Software & Licensing Audit
- **Missing Security Agents**: Identify unprotected systems
- **Version Drift**: Track software version inconsistencies
- **License Compliance**: Monitor commercial software deployments

## Quick Start

### Option 1: Download Pre-built Executable (Recommended)
**No installation required!**

📥 **[Download Latest Release](https://github.com/wslabn/anagnor/releases/latest)**

- **Windows**: `anagnor-windows.exe`
- **Linux**: `anagnor-linux`
- **macOS**: `anagnor-macos`

```bash
# Linux/Mac: Make executable and run
chmod +x anagnor-linux
sudo ./anagnor-linux

# Windows: Run as Administrator
anagnor-windows.exe
```

### Option 2: One-Line Web Install
**Linux/Mac:**
```bash
curl -sSL https://raw.githubusercontent.com/wslabn/anagnor/main/install.sh | sudo bash
```

**Windows (PowerShell as Admin):**
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/wslabn/anagnor/main/install.ps1'))
```

### Option 3: Manual Installation
```bash
git clone https://github.com/wslabn/anagnor.git
cd anagnor
pip install -r requirements.txt
# Install nmap via package manager
python anagnor.py
```

## Configuration

Edit `config.yaml` to customize scanning parameters:

```yaml
# Domain/Active Directory settings (optional)
domain:
  server: "dc.company.com"
  username: "scanner@company.com"
  password: "password"
  base_dn: "DC=company,DC=com"

# Corporate naming conventions
naming_conventions:
  corporate_patterns:
    - "^[A-Z]{2,4}-[0-9]{4,6}$"  # NYC-001234
    - "^WS-[A-Z0-9]{6}$"         # WS-ABC123
  shadow_indicators:
    - ".*[Mm]ac[Bb]ook.*"
    - ".*[Pp]ersonal.*"

# Additional networks to scan
additional_networks:
  - "10.0.0.0/8"
  - "172.16.0.0/12"
```

## Usage

### Basic Scan
```bash
# Auto-discover and scan local networks
anagnor

# Scan specific networks
anagnor --networks 192.168.1.0/24 10.0.0.0/24

# Generate different report formats
anagnor --output html
anagnor --output json
```

### Advanced Usage
```bash
# Use custom configuration
anagnor --config custom_config.yaml

# Save raw results
anagnor --save results.json

# Example with all options
anagnor --config config.yaml --networks 192.168.1.0/24 --output html --save scan_results.json
```

**Note:** Replace `anagnor` with `./anagnor-linux`, `./anagnor-macos`, or `anagnor-windows.exe` if using downloaded executables.

### Programmatic Usage
```python
from anagnor import AnagnorScanner

# Initialize scanner
scanner = AnagnorScanner('config.yaml')

# Run assessment
results = scanner.run_scan(['192.168.1.0/24'])

# Generate report
report_file = scanner.generate_report('html')

# Access specific findings
ghost_assets = results['ghost_inventory']['stale_assets']
iot_devices = results['dark_hardware']['iot_devices']
eol_systems = results['risk_discovery']['eol_systems']
```

## System Requirements

- **Administrator/root privileges** (required for network scanning)
- **Network access** to target ranges
- **nmap** (auto-installed with web installer)
- **Windows 10+, Linux, or macOS**

## Output

### HTML Report
Comprehensive visual report including:
- Executive summary with risk scoring
- Detailed findings by category
- Prioritized recommendations
- Interactive charts and graphs

### JSON Output
Raw structured data for integration with other tools:
```json
{
  "summary": {
    "total_devices": 150,
    "ghost_assets": 12,
    "iot_devices": 8,
    "critical_risks": 5,
    "risk_score": 65
  },
  "ghost_inventory": {
    "stale_assets": [...],
    "shadow_it": [...],
    "unmanaged_devices": [...]
  },
  "dark_hardware": {
    "iot_devices": [...],
    "printers": [...],
    "voip_phones": [...]
  }
}
```

## Key Findings Categories

### 1. Ghost Inventory
- **Stale Domain Assets**: Computers joined to domain but inactive 30+ days
- **Shadow IT Devices**: Personal devices on corporate network
- **Naming Convention Violations**: Devices not following corporate standards

### 2. Dark Hardware
- **IoT Devices**: Smart building systems, sensors, cameras
- **Print Infrastructure**: All printers with model and capability data
- **VoIP Systems**: Phone network topology and devices
- **Hidden Infrastructure**: Unmanaged switches and hubs

### 3. Critical Security Risks
- **End-of-Life Operating Systems**: Unsupported Windows/Linux versions
- **Dangerous Open Ports**: SMB, RDP, and other attack vectors
- **Network Bridging**: Dual-homed systems creating security gaps
- **Vulnerable Services**: Outdated software with known exploits

### 4. Software Management
- **Missing Security Agents**: Systems without antivirus/EDR
- **Version Inconsistencies**: Multiple software versions deployed
- **License Compliance**: Commercial software usage tracking

## Risk Scoring

Anagnor calculates an overall risk score (0-100) based on:
- **Critical Risks** (×10): EOL systems, open dangerous ports
- **High Risks** (×8): Dual-homed machines, missing security agents
- **Medium Risks** (×5): Stale assets, version drift
- **Low Risks** (×2): Shadow IT, unmanaged devices

## Security Considerations

- **Network Access**: Requires network scanning privileges
- **Credentials**: Store AD credentials securely
- **Scanning Impact**: May trigger security alerts
- **Data Sensitivity**: Results contain network topology information

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Run with appropriate privileges for network scanning
sudo ./anagnor-linux  # Linux/Mac
# Or run as Administrator on Windows
```

**LDAP Connection Failed**
- Verify domain controller connectivity
- Check credentials and base DN
- Ensure LDAP ports (389/636) are accessible

**No Devices Found**
- Verify network ranges are correct
- Check firewall rules blocking ICMP/TCP scans
- Ensure target networks are reachable

**Slow Scanning**
- Reduce thread count in config
- Limit port ranges for faster scans
- Use smaller network segments

## Integration

### SIEM Integration
Export JSON results to security information systems:
```python
import json
results = scanner.run_scan()
with open('siem_feed.json', 'w') as f:
    json.dump(results, f)
```

### Asset Management
Integrate with CMDB systems:
```python
devices = results['dark_hardware']['discovered_devices']
for device in devices:
    # Update CMDB with discovered device
    update_cmdb(device)
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-scanner`)
3. Commit changes (`git commit -am 'Add new scanner module'`)
4. Push to branch (`git push origin feature/new-scanner`)
5. Create Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions, issues, or feature requests:
- Create an issue on GitHub
- Contact the development team
- Review documentation and examples

## Roadmap

- [ ] Windows agent deployment for detailed software inventory
- [ ] SNMP-based device discovery and monitoring
- [ ] Integration with vulnerability scanners
- [ ] Automated remediation workflows
- [ ] Real-time monitoring capabilities
- [ ] Cloud infrastructure assessment
- [ ] Mobile device detection and analysis