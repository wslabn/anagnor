# Anagnor Windows Web Installer
# Usage: Run as Administrator in PowerShell:
# iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/wslabn/anagnor/main/install.ps1'))

param(
    [string]$InstallPath = "C:\Program Files\Anagnor"
)

Write-Host "Anagnor Network Assessment Tool - Windows Installer" -ForegroundColor Green
Write-Host "===================================================" -ForegroundColor Green

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Check for Python
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Python not found. Please install Python 3.8+ from python.org" -ForegroundColor Red
    Start-Process "https://www.python.org/downloads/"
    exit 1
}

# Check for Git
Write-Host "Checking Git installation..." -ForegroundColor Yellow
try {
    $gitVersion = git --version 2>&1
    Write-Host "Found: $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "Git not found. Installing Git..." -ForegroundColor Yellow
    # Download and install Git silently
    $gitUrl = "https://github.com/git-for-windows/git/releases/latest/download/Git-2.42.0.2-64-bit.exe"
    $gitInstaller = "$env:TEMP\git-installer.exe"
    Invoke-WebRequest -Uri $gitUrl -OutFile $gitInstaller
    Start-Process -FilePath $gitInstaller -ArgumentList "/SILENT" -Wait
    Remove-Item $gitInstaller
}

# Create installation directory
Write-Host "Creating installation directory..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
Set-Location $InstallPath

# Download Anagnor
Write-Host "Downloading Anagnor..." -ForegroundColor Yellow
if (Test-Path ".git") {
    git pull
} else {
    git clone "https://github.com/wslabn/anagnor.git" .
}

# Install Python dependencies
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Install Nmap (required for network scanning)
Write-Host "Checking Nmap installation..." -ForegroundColor Yellow
try {
    nmap --version | Out-Null
    Write-Host "Nmap already installed" -ForegroundColor Green
} catch {
    Write-Host "Installing Nmap..." -ForegroundColor Yellow
    $nmapUrl = "https://nmap.org/dist/nmap-7.94-setup.exe"
    $nmapInstaller = "$env:TEMP\nmap-installer.exe"
    Invoke-WebRequest -Uri $nmapUrl -OutFile $nmapInstaller
    Start-Process -FilePath $nmapInstaller -ArgumentList "/S" -Wait
    Remove-Item $nmapInstaller
}

# Create batch launcher
Write-Host "Creating launcher..." -ForegroundColor Yellow
$launcherContent = @"
@echo off
cd /d "$InstallPath"
python anagnor.py %*
pause
"@
$launcherContent | Out-File -FilePath "$InstallPath\anagnor.bat" -Encoding ASCII

# Add to PATH
Write-Host "Adding to system PATH..." -ForegroundColor Yellow
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -notlike "*$InstallPath*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$InstallPath", "Machine")
}

# Create desktop shortcut
Write-Host "Creating desktop shortcut..." -ForegroundColor Yellow
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:PUBLIC\Desktop\Anagnor.lnk")
$Shortcut.TargetPath = "$InstallPath\anagnor.bat"
$Shortcut.WorkingDirectory = $InstallPath
$Shortcut.Description = "Anagnor Network Assessment Tool"
$Shortcut.Save()

Write-Host ""
Write-Host "✅ Anagnor installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  1. Open Command Prompt as Administrator"
Write-Host "  2. Run: anagnor"
Write-Host "  3. Or double-click desktop shortcut"
Write-Host ""
Write-Host "Installation directory: $InstallPath" -ForegroundColor Cyan