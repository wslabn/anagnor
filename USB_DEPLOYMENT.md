# Anagnor USB Deployment Guide

## Quick Start Options

### Option 1: Web Install (Recommended)
**Linux/Mac:**
```bash
curl -sSL https://raw.githubusercontent.com/wslabn/anagnor/main/install.sh | sudo bash
```

**Windows (PowerShell as Admin):**
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/wslabn/anagnor/main/install.ps1'))
```

### Option 2: USB Portable Version

#### Building the Portable Version
```bash
# Install build dependencies
pip install pyinstaller

# Make build script executable
chmod +x build_portable.sh

# Build portable version
./build_portable.sh
```

#### USB Structure
```
USB_DRIVE/
├── anagnor.exe          # Standalone executable
├── config.yaml         # Configuration file
├── run_anagnor.bat     # Windows launcher
├── run_anagnor.sh      # Linux/Mac launcher
├── autorun.inf         # Windows autorun
└── README.md           # Documentation
```

#### Usage on Target Systems

**Windows:**
1. Insert USB drive
2. Right-click `run_anagnor.bat`
3. Select "Run as administrator"

**Linux/Mac:**
1. Insert USB drive
2. Open terminal in USB directory
3. Run: `sudo ./run_anagnor.sh`

## System Requirements

### Minimum Requirements
- **OS**: Windows 10+, Linux (Ubuntu 18+), macOS 10.14+
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 500MB free space
- **Network**: Administrative access for scanning

### Required Tools (Auto-installed)
- Python 3.8+
- Nmap network scanner
- ARP-scan (Linux/Mac)

## Network Permissions

Anagnor requires elevated privileges for:
- Network interface access
- Raw socket creation
- ARP table queries
- ICMP ping operations
- Port scanning

## Deployment Scenarios

### 1. Customer Site Assessment
- Use web installer for permanent installation
- Use USB version for one-time assessments
- Generate reports on-site

### 2. Penetration Testing
- Portable USB version recommended
- No installation footprint
- Quick deployment and removal

### 3. Compliance Auditing
- Web installer for recurring scans
- Automated report generation
- Integration with existing tools

## Troubleshooting

### Common Issues

**"Permission Denied" Errors**
- Ensure running as Administrator/root
- Check firewall settings
- Verify network interface access

**"Nmap Not Found"**
- Install nmap manually if auto-install fails
- Add nmap to system PATH
- Use package manager (apt/yum/brew)

**Slow Scanning**
- Reduce network ranges in config.yaml
- Adjust thread count settings
- Use targeted port lists

**No Devices Found**
- Verify network connectivity
- Check IP range configuration
- Ensure target networks are reachable

### Support Commands

**Test Network Connectivity:**
```bash
# Test basic connectivity
ping 8.8.8.8

# Test nmap installation
nmap --version

# Test network interface
ip addr show  # Linux
ifconfig      # Mac
ipconfig      # Windows
```

**Manual Installation:**
```bash
# Clone repository
git clone https://github.com/wslabn/anagnor.git
cd anagnor

# Install dependencies
pip install -r requirements.txt

# Run directly
python anagnor.py
```

## Security Considerations

### Data Handling
- Scan results contain sensitive network information
- Store reports securely
- Delete temporary files after use

### Network Impact
- Scanning may trigger security alerts
- Coordinate with network administrators
- Use during maintenance windows when possible

### Compliance
- Ensure proper authorization before scanning
- Document scan activities
- Follow organizational security policies