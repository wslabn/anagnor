#!/bin/bash
# Anagnor Web Installer - Download and run from web
# Usage: curl -sSL https://raw.githubusercontent.com/wslabn/anagnor/main/install.sh | sudo bash

set -e

REPO_URL="https://github.com/wslabn/anagnor"
INSTALL_DIR="/opt/anagnor"
BIN_DIR="/usr/local/bin"

echo "Anagnor Network Assessment Tool - Web Installer"
echo "==============================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: curl -sSL https://raw.githubusercontent.com/wslabn/anagnor/main/install.sh | sudo bash"
    exit 1
fi

# Check for nmap
echo "Checking nmap installation..."
if ! command -v nmap &> /dev/null; then
    echo "Installing nmap..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y nmap
    elif command -v yum &> /dev/null; then
        yum install -y nmap
    elif command -v dnf &> /dev/null; then
        dnf install -y nmap
    else
        echo "Please install nmap manually"
        exit 1
    fi
else
    echo "Nmap already installed"
fi

# Create installation directory
echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Download Anagnor
echo "Downloading Anagnor..."
if [ -d ".git" ]; then
    git pull
else
    git clone "$REPO_URL" .
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Create launcher script
echo "Creating launcher script..."
cat > "$BIN_DIR/anagnor" << EOF
#!/bin/bash
cd "$INSTALL_DIR"
python3 anagnor.py "\$@"
EOF

chmod +x "$BIN_DIR/anagnor"

# Create desktop shortcut (if GUI available)
if [ -n "$DISPLAY" ] && command -v xdg-desktop-menu &> /dev/null; then
    cat > /usr/share/applications/anagnor.desktop << EOF
[Desktop Entry]
Name=Anagnor Network Scanner
Comment=Network Assessment Tool
Exec=gnome-terminal -- sudo anagnor
Icon=network-workgroup
Terminal=true
Type=Application
Categories=Network;Security;
EOF
    xdg-desktop-menu install /usr/share/applications/anagnor.desktop
fi

echo ""
echo "✅ Anagnor installed successfully!"
echo ""
echo "Usage:"
echo "  anagnor                          # Auto-discover and scan"
echo "  anagnor --networks 192.168.1.0/24  # Scan specific network"
echo "  anagnor --help                   # Show all options"
echo ""
echo "Files installed to: $INSTALL_DIR"
echo "Executable available as: anagnor"