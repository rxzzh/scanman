# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller 配置文件 - 用于构建漏洞扫描报告生成器
优化版本，确保所有依赖和资源文件都被正确打包
"""

import os
from pathlib import Path

# 获取项目根目录
project_root = Path(os.getcwd())
static_path = project_root / 'static'

# 收集所有静态文件
datas = []
if static_path.exists():
    for docx_file in static_path.glob('*.docx'):
        datas.append((str(docx_file), 'static'))

# 隐式导入的模块
hiddenimports = [
    'pydantic',
    'openpyxl',
    'docx',
    'lxml',
    'lxml.etree',
    'lxml._elementpath',
    'pandas',
    'rich',
    'rich.console',
    'rich.table',
    'rich.progress',
    'tqdm',
    'tabulate',
    'plotext',
    'tkinter',
    'tkinter.ttk',
    'tkinter.filedialog',
    'tkinter.messagebox',
    'PIL',
    'PIL._tkinter_finder',
    'scanman',
    'scanman.core',
    'scanman.model',
    'scanman.read',
    'scanman.utils',
    'scanman.build',
]

# 排除不需要的模块以减小文件大小
excludes = [
    'matplotlib',
    'numpy.distutils',
    'distutils',
    'setuptools',
    'pip',
    'wheel',
    'pytest',
    'test',
    'unittest',
    'pydoc',
    'doctest',
]

block_cipher = None

a = Analysis(
    ['gui.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# 过滤掉一些不需要的文件
a.datas = [x for x in a.datas if not any(exclude in x[0].lower() for exclude in [
    'test', 'tests', '__pycache__', '.pyc', '.pyo'
])]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='scanman',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # 启用UPX压缩以减小文件大小
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,   # 显示控制台窗口以便用户看到有效信息
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # 如果有图标文件可以在这里指定
    version_file=None,  # 如果有版本信息文件可以在这里指定
)
