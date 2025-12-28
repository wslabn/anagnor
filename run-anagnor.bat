@echo off
echo Anagnor Network Assessment Tool
echo ===============================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo ERROR: Please run as Administrator
    echo Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo Starting network assessment...
echo.

REM Run Anagnor
windows-anagnor.exe %*

echo.
echo Scan complete! Check the generated report files.
pause