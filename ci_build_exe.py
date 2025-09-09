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

def ensure_requirements():
    """确保所需的依赖已安装"""
    print("检查并安装构建依赖...")
    try:
        import PyInstaller
        print("✓ PyInstaller 已安装")
    except ImportError:
        print("安装 PyInstaller...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
    
    # 安装项目依赖
    if os.path.exists("requirements.txt"):
        print("安装项目依赖...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)

def clean_build_dirs():
    """清理构建目录"""
    print("清理构建目录...")
    dirs_to_clean = ["build", "dist", "__pycache__"]
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"✓ 已清理 {dir_name}")

def build_executable():
    """构建可执行文件"""
    print("开始构建可执行文件...")
    
    # 检查是否存在优化的spec文件
    spec_file = "build.spec"
    if os.path.exists(spec_file):
        print(f"使用优化的spec文件: {spec_file}")
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--distpath=dist",              # 指定输出目录
            "--workpath=build",             # 指定工作目录
            spec_file                       # 使用spec文件
        ]
    else:
        print("使用默认构建参数...")
        # 构建命令参数
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",                    # 打包成单个文件
            "--noconsole",                  # 不显示控制台窗口 (GUI应用)
            "--name=漏洞扫描报告生成器",        # 指定输出文件名
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
    
    print(f"执行命令: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("✓ 构建成功!")
        if result.stdout:
            print("构建输出:")
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ 构建失败: {e}")
        print(f"错误输出: {e.stderr}")
        if e.stdout:
            print(f"标准输出: {e.stdout}")
        return False

def copy_additional_files():
    """复制额外的必需文件到dist目录"""
    print("复制额外文件...")
    
    # 确保static文件夹被复制（作为备份）
    static_src = Path("static")
    static_dst = Path("dist/static")
    
    if static_src.exists():
        if static_dst.exists():
            shutil.rmtree(static_dst)
        shutil.copytree(static_src, static_dst)
        print("✓ 已复制 static 文件夹")
    
    # 复制其他重要文件
    important_files = ["README.md"]
    for file_name in important_files:
        src_file = Path(file_name)
        if src_file.exists():
            dst_file = Path("dist") / file_name
            shutil.copy2(src_file, dst_file)
            print(f"✓ 已复制 {file_name}")

def verify_build():
    """验证构建结果"""
    print("验证构建结果...")
    
    exe_name = "漏洞扫描报告生成器.exe" if os.name == 'nt' else "漏洞扫描报告生成器"
    exe_path = Path("dist") / exe_name
    
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"✓ 可执行文件已生成: {exe_path}")
        print(f"✓ 文件大小: {size_mb:.2f} MB")
        
        # 检查static文件夹
        static_path = Path("dist/static")
        if static_path.exists():
            template_files = list(static_path.glob("*.docx"))
            print(f"✓ 模板文件数量: {len(template_files)}")
            for template in template_files:
                print(f"  - {template.name}")
        else:
            print("⚠ 警告: static文件夹未找到")
        
        return True
    else:
        print(f"✗ 可执行文件未找到: {exe_path}")
        return False

def main():
    """主函数"""
    print("=" * 50)
    print("漏洞扫描报告生成器 - CI构建脚本")
    print("=" * 50)
    
    try:
        # 检查当前目录
        if not os.path.exists("gui.py"):
            print("✗ 错误: 未找到 gui.py 文件，请在项目根目录运行此脚本")
            sys.exit(1)
        
        # 执行构建步骤
        ensure_requirements()
        clean_build_dirs()
        
        if not build_executable():
            sys.exit(1)
        
        copy_additional_files()
        
        if verify_build():
            print("\n" + "=" * 50)
            print("✓ 构建完成！")
            print("✓ 可执行文件位于 dist/ 目录")
            print("=" * 50)
        else:
            print("\n" + "=" * 50)
            print("✗ 构建验证失败")
            print("=" * 50)
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n用户中断构建")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ 构建过程中发生错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
