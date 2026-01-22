@echo off
REM Windows Build Script for SSH Terminal Manager
REM Creates a standalone executable and optionally an installer

echo ========================================
echo SSH Terminal Manager - Windows Build
echo ========================================

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH
    exit /b 1
)

REM Create virtual environment if not exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate venv
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
pip install pyinstaller

REM Create icon if not exists (convert SVG to ICO would require additional tools)
if not exist "src\resources\icons\terminal.ico" (
    echo Note: terminal.ico not found, building without icon
)

REM Build with PyInstaller
echo Building executable...
pyinstaller ssh_terminal.spec --clean

REM Check if Inno Setup is installed
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    echo Building installer with Inno Setup...
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" build_scripts\windows_installer.iss
) else (
    echo Inno Setup not found - skipping installer creation
    echo Download from: https://jrsoftware.org/isdl.php
)

echo ========================================
echo Build complete!
echo Executable: dist\SSHTerminalManager\SSHTerminalManager.exe
if exist "dist\SSHTerminalManager_Setup.exe" (
    echo Installer: dist\SSHTerminalManager_Setup.exe
)
echo ========================================

pause
