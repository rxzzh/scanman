#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CI构建脚本 - 用于生成漏洞扫描报告生成器可执行文件
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# 设置控制台编码为UTF-8，避免在Windows环境中出现中文显示问题
def safe_print(text):
    """安全的打印函数，避免编码问题"""
    try:
        print(text)
    except UnicodeEncodeError:
        # 如果出现编码错误，使用ASCII安全模式
        safe_text = text.encode('ascii', 'replace').decode('ascii')
        print(safe_text)

if sys.platform == 'win32':
    import locale
    try:
        # 尝试设置控制台编码为UTF-8
        os.system('chcp 65001 >nul 2>&1')
        # 重新配置标准输出编码
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
    except:
        # 如果设置失败，使用ASCII安全模式
        pass

def ensure_requirements():
    """确保所需的依赖已安装"""
    safe_print("Checking and installing build dependencies...")
    try:
        import PyInstaller
        safe_print("✓ PyInstaller installed")
    except ImportError:
        safe_print("Installing PyInstaller...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
    
    # 安装项目依赖
    if os.path.exists("requirements.txt"):
        safe_print("Installing project dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)

def clean_build_dirs():
    """清理构建目录"""
    safe_print("Cleaning build directories...")
    dirs_to_clean = ["build", "dist", "__pycache__"]
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            safe_print(f"✓ Cleaned {dir_name}")

def build_executable():
    """构建可执行文件"""
    safe_print("Starting executable build...")
    
    # 检查是否存在优化的spec文件
    spec_file = "build.spec"
    if os.path.exists(spec_file):
        safe_print(f"Using optimized spec file: {spec_file}")
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--distpath=dist",              # 指定输出目录
            "--workpath=build",             # 指定工作目录
            spec_file                       # 使用spec文件
        ]
    else:
        safe_print("Using default build parameters...")
        # 构建命令参数
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",                    # 打包成单个文件
            "--console",                    # 显示控制台窗口以便用户看到有效信息
            "--name=ScanReportGenerator",     # 指定输出文件名
            "--add-data=static;static",     # 添加static文件夹到打包中 (Windows格式)
            "--distpath=dist",              # 指定输出目录
            "--workpath=build",             # 指定工作目录
            "--specpath=.",                 # spec文件位置
            "--hidden-import=pydantic",     # 隐式导入
            "--hidden-import=openpyxl",
            "--hidden-import=docx",
            "--hidden-import=lxml",
            "--hidden-import=pandas",
            "--hidden-import=rich",
            "--hidden-import=tqdm",
            "--hidden-import=tabulate",
            "--hidden-import=plotext",
            "--hidden-import=tkinter",
            "--hidden-import=tkinter.ttk",
            "--hidden-import=tkinter.filedialog",
            "--hidden-import=tkinter.messagebox",
            "gui.py"                        # 主入口文件
        ]
        
        # 在Linux/Mac上使用冒号分隔符
        if os.name != 'nt':
            # 替换Windows格式的add-data参数
            for i, arg in enumerate(cmd):
                if arg.startswith("--add-data=static;static"):
                    cmd[i] = "--add-data=static:static"
                    break
    
    safe_print(f"Executing command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        safe_print("✓ Build successful!")
        if result.stdout:
            safe_print("Build output:")
            safe_print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        safe_print(f"✗ Build failed: {e}")
        safe_print(f"Error output: {e.stderr}")
        if e.stdout:
            safe_print(f"Standard output: {e.stdout}")
        return False

def copy_additional_files():
    """复制额外的必需文件到dist目录"""
    safe_print("Copying additional files...")
    
    # 确保static文件夹被复制（作为备份）
    static_src = Path("static")
    static_dst = Path("dist/static")
    
    if static_src.exists():
        if static_dst.exists():
            shutil.rmtree(static_dst)
        shutil.copytree(static_src, static_dst)
        safe_print("✓ Copied static folder")
    
    # 复制其他重要文件
    important_files = ["README.md"]
    for file_name in important_files:
        src_file = Path(file_name)
        if src_file.exists():
            dst_file = Path("dist") / file_name
            shutil.copy2(src_file, dst_file)
            safe_print(f"✓ Copied {file_name}")

def verify_build():
    """验证构建结果"""
    safe_print("Verifying build results...")
    
    exe_name = "ScanReportGenerator.exe" if os.name == 'nt' else "ScanReportGenerator"
    exe_path = Path("dist") / exe_name
    
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        safe_print(f"✓ Executable generated: {exe_path}")
        safe_print(f"✓ File size: {size_mb:.2f} MB")
        
        # 检查static文件夹
        static_path = Path("dist/static")
        if static_path.exists():
            template_files = list(static_path.glob("*.docx"))
            safe_print(f"✓ Template files count: {len(template_files)}")
            for template in template_files:
                safe_print(f"  - {template.name}")
        else:
            safe_print("⚠ Warning: static folder not found")
        
        return True
    else:
        safe_print(f"✗ Executable not found: {exe_path}")
        return False

def main():
    """主函数"""
    safe_print("=" * 50)
    safe_print("Vulnerability Scan Report Generator - CI Build Script")
    safe_print("=" * 50)
    
    try:
        # 检查当前目录
        if not os.path.exists("gui.py"):
            safe_print("✗ Error: gui.py not found, please run this script in the project root directory")
            sys.exit(1)
        
        # 执行构建步骤
        ensure_requirements()
        clean_build_dirs()
        
        if not build_executable():
            sys.exit(1)
        
        copy_additional_files()
        
        if verify_build():
            safe_print("\n" + "=" * 50)
            safe_print("✓ Build completed!")
            safe_print("✓ Executable located in dist/ directory")
            safe_print("=" * 50)
        else:
            safe_print("\n" + "=" * 50)
            safe_print("✗ Build verification failed")
            safe_print("=" * 50)
            sys.exit(1)
            
    except KeyboardInterrupt:
        safe_print("\nBuild interrupted by user")
        sys.exit(1)
    except Exception as e:
        safe_print(f"\n✗ Error occurred during build: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
