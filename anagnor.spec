# -*- mode: python ; coding: utf-8 -*-

import sys
import os

block_cipher = None

# Platform-specific configurations
if sys.platform == 'win32':
    console = True
    icon = None
else:
    console = True
    icon = None

a = Analysis(
    ['anagnor.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('config.yaml', '.'),
        ('modules', 'modules'),
        ('utils', 'utils'),
    ],
    hiddenimports=[
        'yaml',
        'jinja2',
        'colorama',
        'tabulate',
        'requests',
        'psutil',
        'netifaces',
        'socket',
        'subprocess',
        'threading',
        'concurrent.futures',
        'ipaddress',
        'datetime',
        'json',
        'logging',
        'pathlib',
        're',
        'collections',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'ldap',
        'paramiko',
        'impacket',
        'scapy',
        'nmap',
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
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='anagnor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=console,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon,
)