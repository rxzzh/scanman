# 构建说明文档

## 本地构建

### 方式一：使用CI构建脚本（推荐）

```bash
# 运行构建脚本
python ci_build_exe.py
```

### 方式二：手动构建

```bash
# 安装依赖
pip install -r requirements.txt
pip install pyinstaller

# 使用优化的spec文件构建
pyinstaller --distpath=dist --workpath=build build.spec

# 或使用基础命令构建
pyinstaller --onefile --noconsole --name=漏洞扫描报告生成器 --add-data="static;static" gui.py
```

## 自动化构建和发布

### GitHub Actions 工作流

当代码推送到 `main` 分支时，会自动触发构建和发布流程：

1. **构建环境**: Windows Server 2022 (windows-latest), Python 3.11
2. **构建产物**: 
   - `漏洞扫描报告生成器.exe` - 主程序
   - `static/` 文件夹 - Word模板文件
   - `README.md` - 使用说明
3. **发布**: 自动创建GitHub Release并上传构建产物

### 工作流文件位置

- `.github/workflows/build-and-release.yml` - 主构建和发布工作流
- `ci_build_exe.py` - CI构建脚本
- `build.spec` - 优化的PyInstaller配置文件

## 构建产物说明

### 文件结构
```
dist/
├── 漏洞扫描报告生成器.exe  # 主程序可执行文件
├── static/                 # 模板文件夹（必需）
│   ├── template-subtotal.docx
│   ├── template-target.docx
│   ├── template-vulnlist-E.docx
│   ├── template-vulnlist-mini.docx
│   ├── template-vulnlist-v2-mini.docx
│   ├── template-vulnlist-v2.docx
│   └── template-vulnlist.docx
└── README.md              # 使用说明
```

### 重要提醒

⚠️ **static文件夹是程序运行的必需部分**，包含了Word报告模板文件。如果缺少此文件夹，程序将无法正常生成报告。

## 构建优化

### PyInstaller优化配置

`build.spec` 文件包含以下优化：

1. **隐式导入**: 自动包含所有必需的Python模块
2. **资源文件**: 自动打包static文件夹中的模板文件
3. **文件过滤**: 排除测试文件和缓存文件以减小体积
4. **UPX压缩**: 启用压缩以减小可执行文件大小
5. **GUI模式**: 不显示控制台窗口

### 依赖管理

项目依赖在 `requirements.txt` 中定义，包括：
- GUI框架: tkinter (内置)
- 文档处理: python-docx, lxml
- 数据处理: pandas, openpyxl
- 界面美化: rich, tqdm
- 数据验证: pydantic

## 故障排除

### 常见问题

1. **模块导入错误**: 检查 `build.spec` 中的 `hiddenimports` 列表
2. **资源文件缺失**: 确保 `static` 文件夹正确打包
3. **构建失败**: 检查Python版本和依赖是否正确安装

### 调试构建

```bash
# 启用详细输出
pyinstaller --log-level DEBUG build.spec

# 检查依赖
python -c "import scanman; print('导入成功')"
```

## 版本控制

- 发布版本格式: `vYYYY-MM-DD-HHMM`
- 每次推送到main分支都会创建新的release
- Release包含完整的可执行文件和模板文件
