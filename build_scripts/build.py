#!/usr/bin/env python3
"""
Cross-platform build script for SSH Terminal Manager.
Run with: python build_scripts/build.py
"""

import os
import sys
import subprocess
import shutil
import platform

VERSION = "1.0.0"
APP_NAME = "SSHTerminalManager"

def get_project_root():
    """Get the project root directory."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run_command(cmd, cwd=None):
    """Run a command and print output."""
    print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(cmd, cwd=cwd, shell=isinstance(cmd, str))
    if result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        sys.exit(1)

def ensure_venv():
    """Ensure virtual environment exists and is activated."""
    project_root = get_project_root()
    venv_path = os.path.join(project_root, "venv")

    if not os.path.exists(venv_path):
        print("Creating virtual environment...")
        run_command([sys.executable, "-m", "venv", "venv"], cwd=project_root)

    # Get the Python executable in the venv
    if platform.system() == "Windows":
        venv_python = os.path.join(venv_path, "Scripts", "python.exe")
        venv_pip = os.path.join(venv_path, "Scripts", "pip.exe")
    else:
        venv_python = os.path.join(venv_path, "bin", "python")
        venv_pip = os.path.join(venv_path, "bin", "pip")

    return venv_python, venv_pip

def install_dependencies(pip_path):
    """Install required dependencies."""
    project_root = get_project_root()
    print("Installing dependencies...")
    run_command([pip_path, "install", "-r", "requirements.txt"], cwd=project_root)
    run_command([pip_path, "install", "pyinstaller"], cwd=project_root)

def build_executable(python_path):
    """Build the executable using PyInstaller."""
    project_root = get_project_root()
    print("Building executable with PyInstaller...")

    # Clean previous builds
    dist_path = os.path.join(project_root, "dist")
    build_path = os.path.join(project_root, "build")
    if os.path.exists(dist_path):
        shutil.rmtree(dist_path)
    if os.path.exists(build_path):
        shutil.rmtree(build_path)

    run_command([python_path, "-m", "PyInstaller", "ssh_terminal.spec", "--clean"], cwd=project_root)

def build_windows_installer():
    """Build Windows installer using Inno Setup."""
    project_root = get_project_root()

    # Check for Inno Setup
    inno_paths = [
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
    ]

    inno_path = None
    for path in inno_paths:
        if os.path.exists(path):
            inno_path = path
            break

    if inno_path:
        print("Building Windows installer with Inno Setup...")
        iss_file = os.path.join(project_root, "build_scripts", "windows_installer.iss")
        run_command([inno_path, iss_file])
    else:
        print("Inno Setup not found - skipping installer creation")
        print("Download from: https://jrsoftware.org/isdl.php")

def main():
    """Main build function."""
    system = platform.system()
    project_root = get_project_root()

    print("=" * 50)
    print(f"SSH Terminal Manager - Build Script")
    print(f"Platform: {system}")
    print(f"Version: {VERSION}")
    print("=" * 50)

    # Setup virtual environment
    venv_python, venv_pip = ensure_venv()

    # Install dependencies
    install_dependencies(venv_pip)

    # Build executable
    build_executable(venv_python)

    # Platform-specific installer
    if system == "Windows":
        build_windows_installer()
    elif system == "Darwin":
        print("\nTo create a DMG installer, run:")
        print("  ./build_scripts/build_macos.sh")
    elif system == "Linux":
        print("\nTo create AppImage and .deb, run:")
        print("  ./build_scripts/build_linux.sh")

    print("\n" + "=" * 50)
    print("Build complete!")
    print(f"Output: {os.path.join(project_root, 'dist', APP_NAME)}")
    print("=" * 50)

if __name__ == "__main__":
    main()
