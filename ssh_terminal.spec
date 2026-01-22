# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for SSH Terminal Manager.
Build with: pyinstaller ssh_terminal.spec
"""

import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect all data files
datas = [
    ('config/settings.json', 'config'),
    ('src/styles/dark_theme.qss', 'src/styles'),
    ('src/resources/icons/*.svg', 'src/resources/icons'),
]

# Hidden imports that PyInstaller might miss
hiddenimports = [
    'paramiko',
    'pyte',
    'cryptography',
    'keyring',
    'keyring.backends',
    'keyring.backends.Windows',
    'bcrypt',
    'nacl',
    'cffi',
    'pkg_resources.py2_warn',
]

# Platform-specific settings
if sys.platform == 'win32':
    icon_file = 'src/resources/icons/terminal.ico' if os.path.exists('src/resources/icons/terminal.ico') else None
    console = False
elif sys.platform == 'darwin':
    icon_file = 'src/resources/icons/terminal.icns' if os.path.exists('src/resources/icons/terminal.icns') else None
    console = False
else:
    icon_file = None
    console = False

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'cv2',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SSHTerminalManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=console,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_file,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SSHTerminalManager',
)

# macOS specific: Create .app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='SSH Terminal Manager.app',
        icon=icon_file,
        bundle_identifier='com.sshterminal.manager',
        info_plist={
            'CFBundleName': 'SSH Terminal Manager',
            'CFBundleDisplayName': 'SSH Terminal Manager',
            'CFBundleVersion': '1.0.0',
            'CFBundleShortVersionString': '1.0.0',
            'NSHighResolutionCapable': True,
            'LSMinimumSystemVersion': '10.13.0',
        },
    )
