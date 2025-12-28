#!/bin/bash
# Build script for Anagnor portable executable

echo "Building Anagnor Portable Network Assessment Tool..."

# Install PyInstaller if not present
pip install pyinstaller

# Clean previous builds
rm -rf build/ dist/

# Build standalone executable
pyinstaller anagnor.spec --clean

# Create portable package structure
mkdir -p portable/
cp dist/anagnor portable/
cp config.yaml portable/
cp README.md portable/
cp requirements.txt portable/

# Create launcher script
cat > portable/run_anagnor.sh << 'EOF'
#!/bin/bash
echo "Anagnor Network Assessment Tool"
echo "==============================="
echo "Checking system requirements..."

# Check if running as root (required for network scanning)
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root for network scanning capabilities:"
    echo "sudo ./run_anagnor.sh"
    exit 1
fi

# Check for nmap
if ! command -v nmap &> /dev/null; then
    echo "Installing nmap..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y nmap
    elif command -v yum &> /dev/null; then
        yum install -y nmap
    else
        echo "Please install nmap manually"
        exit 1
    fi
fi

echo "Starting Anagnor scan..."
./anagnor "$@"
EOF

chmod +x portable/run_anagnor.sh

# Create Windows batch file
cat > portable/run_anagnor.bat << 'EOF'
@echo off
echo Anagnor Network Assessment Tool
echo ===============================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo Please run as Administrator for full functionality
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo Starting Anagnor scan...
anagnor.exe %*
pause
EOF

echo "Portable package created in 'portable/' directory"
echo "Contents:"
ls -la portable/

echo ""
echo "To use:"
echo "1. Copy 'portable/' folder to USB drive"
echo "2. On target system, run:"
echo "   Linux/Mac: sudo ./run_anagnor.sh"
echo "   Windows: Right-click run_anagnor.bat -> Run as administrator"