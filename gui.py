
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scanman.core import Prime, ScannerType, TableType
import json

class RuleRow(ttk.Frame):
    """A single row in the rule builder GUI, representing one condition."""
    FIELD_MAP = {'名称': 'name', '严重程度': 'severity', 'IP': 'ip', '描述': 'description', '解决方法': 'solution'}
    OPERATOR_MAP = {
        '包含': 'contains', '不包含': 'not contains',
        '等于': 'equal', '不等于': 'not equal',
        '在列表...中': 'in', '不在列表...中': 'not in'
    }

    def __init__(self, master, on_delete):
        super().__init__(master)
        self.on_delete = on_delete

        self.field_var = tk.StringVar()
        self.op_var = tk.StringVar()

        self.field_combo = ttk.Combobox(self, textvariable=self.field_var, values=list(self.FIELD_MAP.keys()), width=12)
        self.op_combo = ttk.Combobox(self, textvariable=self.op_var, values=list(self.OPERATOR_MAP.keys()), width=12)
        self.value_entry = ttk.Entry(self, width=30)
        self.delete_btn = ttk.Button(self, text="-", command=self.on_delete, width=3)

        self.field_combo.pack(side="left", padx=2)
        self.op_combo.pack(side="left", padx=2)
        self.value_entry.pack(side="left", padx=2, expand=True, fill="x")
        self.delete_btn.pack(side="left", padx=2)

        self.field_var.set(list(self.FIELD_MAP.keys())[0])
        self.op_var.set(list(self.OPERATOR_MAP.keys())[0])

    def get_rule(self):
        field = self.FIELD_MAP.get(self.field_var.get())
        op = self.OPERATOR_MAP.get(self.op_var.get())
        value = self.value_entry.get().strip()

        if op in ['in', 'not in']:
            # Split by comma and strip whitespace for list values
            value = [item.strip() for item in value.split(',') if item.strip()]

        if not all([field, op, value]):
            return None # Incomplete rule
        
        return {"field": field, "operator": op, "value": value}

class RuleGroup(ttk.Frame):
    """A group of rules, which can be nested."""
    def __init__(self, master, is_root=False, on_delete=None):
        super().__init__(master, relief="groove", borderwidth=2)
        self.is_root = is_root
        self.on_delete = on_delete
        self.rules = []

        # Top control frame for logic, NOT, and delete
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(top_frame, text="匹配").pack(side="left")
        self.logic_var = tk.StringVar(value="所有(AND)")
        ttk.Combobox(top_frame, textvariable=self.logic_var, values=["所有(AND)", "任意(OR)"], width=10).pack(side="left", padx=5)
        ttk.Label(top_frame, text="以下规则").pack(side="left")

        self.not_var = tk.BooleanVar()
        ttk.Checkbutton(top_frame, text="反转此组(NOT)", variable=self.not_var).pack(side="left", padx=10)

        if not self.is_root:
            ttk.Button(top_frame, text="删除此组", command=self.on_delete).pack(side="right")

        # Frame to hold the actual rule rows and subgroups
        self.rules_frame = ttk.Frame(self)
        self.rules_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Bottom control frame for adding new rules/groups
        bottom_frame = ttk.Frame(self)
        bottom_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(bottom_frame, text="+ 添加规则", command=self.add_rule).pack(side="left")
        ttk.Button(bottom_frame, text="+ 添加规则组", command=self.add_group).pack(side="left", padx=5)

    def add_rule(self):
        rule_row = RuleRow(self.rules_frame, on_delete=lambda: self.remove_widget(rule_row))
        rule_row.pack(fill="x", pady=2)
        self.rules.append(rule_row)

    def add_group(self):
        rule_group = RuleGroup(self.rules_frame, on_delete=lambda: self.remove_widget(rule_group))
        rule_group.pack(fill="both", expand=True, pady=5, padx=10) # Indent subgroups
        self.rules.append(rule_group)

    def remove_widget(self, widget):
        if widget in self.rules:
            self.rules.remove(widget)
        widget.destroy()

    def get_rule(self):
        child_rules = [child.get_rule() for child in self.rules if child.get_rule() is not None]

        if not child_rules:
            return None

        logic = "AND" if self.logic_var.get() == "所有(AND)" else "OR"
        
        group_rule = {
            "logical_operator": logic,
            "rules": child_rules
        }

        if self.not_var.get():
            return {
                "logical_operator": "NOT",
                "rules": [group_rule]
            }
        else:
            return group_rule


class VulnerabilityScanReportGenerator:
    def __init__(self, master):
        self.master = master
        master.title("Vulnerability Scan Report Generator by rxzzh")
        self.create_widgets()

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(padx=10, pady=10, expand=True, fill="both")

        self.basic_frame = ttk.Frame(self.notebook)
        self.advanced_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.basic_frame, text='基本选项')
        self.notebook.add(self.advanced_frame, text='高级过滤')

        self.create_basic_widgets(self.basic_frame)
        self.create_advanced_widgets(self.advanced_frame)
        
        button_frame = ttk.Frame(self.master)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="运行", command=self.run).pack(side="left", padx=5)
        ttk.Button(button_frame, text="退出", command=self.master.quit).pack(side="left", padx=5)

    def create_basic_widgets(self, frame):
        # Widgets are placed in a frame for better organization
        ttk.Label(frame, text="漏扫报告html文件夹路径（必填）").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.html_path = ttk.Entry(frame, width=50)
        self.html_path.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="浏览", command=lambda: self.browse_folder(self.html_path)).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(frame, text="表格类型").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.table_type = ttk.Combobox(frame, values=["YPG", "DJCP", "DJCP_MINI", "YPG_MINI", "DEV_PORT"])
        self.table_type.set("DJCP")
        self.table_type.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(frame, text="扫描器类型（默认自动选择）").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.scanner_type = ttk.Combobox(frame, values=["RSAS", "XLSX", "WANGSHEN", "NSFOCUS", "GREEN_LEAGUE", "AUTO"])
        self.scanner_type.set("AUTO")
        self.scanner_type.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(frame, text="漏扫目标信息Excel表路径（仅YPG需要）").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.xlsx_path = ttk.Entry(frame, width=50)
        self.xlsx_path.grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(frame, text="浏览", command=lambda: self.browse_file(self.xlsx_path, [("Excel Files", "*.xlsx")])).grid(row=3, column=2, padx=5, pady=5)

        ttk.Label(frame, text="Word格式报告输出路径及前缀").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.output_path = ttk.Entry(frame, width=50)
        self.output_path.insert(0, "./转格式")
        self.output_path.grid(row=4, column=1, padx=5, pady=5)
        ttk.Button(frame, text="浏览", command=lambda: self.browse_file(self.output_path, [("Word Document", "*.docx")], save=True)).grid(row=4, column=2, padx=5, pady=5)

        ttk.Label(frame, text="漏扫目标表格输出路径（仅DEV_PORT需要）").grid(row=7, column=0, sticky="w", padx=5, pady=5)
        self.target_path = ttk.Entry(frame, width=50)
        self.target_path.grid(row=7, column=1, padx=5, pady=5)
        ttk.Button(frame, text="浏览", command=lambda: self.browse_file(self.target_path, [("Excel Files", "*.xlsx")], save=True)).grid(row=7, column=2, padx=5, pady=5)

        ttk.Label(frame, text="限制每个漏洞的IP数量（-1不限制）").grid(row=8, column=0, sticky="w", padx=5, pady=5)
        self.limit_result = ttk.Entry(frame, width=50)
        self.limit_result.insert(0, "-1")
        self.limit_result.grid(row=8, column=1, padx=5, pady=5, sticky="ew")

        # Checkboxes in their own frame
        check_frame = ttk.Frame(frame)
        check_frame.grid(row=5, column=0, columnspan=3, sticky="w", padx=5, pady=5)
        self.recursive = tk.BooleanVar(value=True)
        ttk.Checkbutton(check_frame, text="递归读取子文件夹下所有ip.html", variable=self.recursive).pack(side="left")
        self.quiet = tk.BooleanVar()
        ttk.Checkbutton(check_frame, text="安静模式", variable=self.quiet).pack(side="left", padx=10)
        self.suspicious = tk.BooleanVar()
        ttk.Checkbutton(check_frame, text="SUS", variable=self.suspicious).pack(side="left", padx=10)
        
        frame.columnconfigure(1, weight=1)

    def create_advanced_widgets(self, frame):
        self.filter_enabled = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="启用高级过滤", variable=self.filter_enabled).pack(anchor="w", padx=5, pady=5)
        
        # This frame will contain the dynamic rule builder
        builder_frame = ttk.Frame(frame)
        builder_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.root_rule_group = RuleGroup(builder_frame, is_root=True)
        self.root_rule_group.pack(fill="both", expand=True)
        
    def browse_folder(self, entry):
        folder_path = filedialog.askdirectory()
        if folder_path:
            entry.delete(0, tk.END)
            entry.insert(0, folder_path)

    def browse_file(self, entry, file_types, save=False):
        if save:
            file_path = filedialog.asksaveasfilename(filetypes=file_types)
        else:
            file_path = filedialog.askopenfilename(filetypes=file_types)
        if file_path:
            entry.delete(0, tk.END)
            entry.insert(0, file_path)

    def run(self):
        try:
            prime = Prime()
            prime.set_html_path(self.html_path.get())
            prime.set_xlsx_path(self.xlsx_path.get())
            prime.set_output_full_path(self.output_path.get())
            prime.set_recursive_read(self.recursive.get())
            prime.set_target(self.target_path.get())
            prime.set_limit_result_amount(limit=int(self.limit_result.get()))

            if self.filter_enabled.get():
                rules = self.root_rule_group.get_rule()
                if rules:
                    prime.set_filter_rules(rules)
                    prime.set_filter_enabled(True)
                else:
                    prime.set_filter_enabled(False)
            else:
                prime.set_filter_enabled(False)

            table_type_mapping = {
                "YPG": TableType.YPG, "DJCP": TableType.DJCP,
                "DJCP_MINI": TableType.DJCP_MINI, "YPG_MINI": TableType.YPG_MINI,
                "DEV_PORT": TableType.DEV_PORT,
            }
            prime.set_table_type(table_type_mapping[self.table_type.get()])

            scanner_type_mapping = {
                "RSAS": ScannerType.RSAS, "XLSX": ScannerType.XLSX,
                "WANGSHEN": ScannerType.WANGSHEN, "NSFOCUS": ScannerType.NSFOCUS,
                "GREEN_LEAGUE": ScannerType.GREEN_LEAGUE, "AUTO": ScannerType.AUTO
            }
            prime.set_scanner_type(scanner_type_mapping[self.scanner_type.get()])
            prime.set_quiet(quiet=self.quiet.get())
            prime.set_suspicious(suspicious=self.suspicious.get())

            prime.go()

            completion_message = f"处理完成！\n\nWord格式报告已输出到：{self.output_path.get()}"
            if self.target_path.get():
                completion_message += f"\n\n漏扫目标表格已输出到：{self.target_path.get()}"
            messagebox.showinfo("成功", completion_message)
        except ValueError as ve:
            messagebox.showerror("错误", str(ve))
        except Exception as e:
            messagebox.showerror("错误", f"发生错误：{str(e)}\n路径下是否包含x.x.x.x.html的漏扫报告？")

def main():
    root = tk.Tk()
    app = VulnerabilityScanReportGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()