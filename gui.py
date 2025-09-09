import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scanman.core import Prime, ScannerType, TableType

class VulnerabilityScanReportGenerator:
    def __init__(self, master):
        self.master = master
        master.title("Vulnerability Scan Report Generator by rxzzh")

        self.create_widgets()

    def create_widgets(self):
        # HTML Path
        ttk.Label(self.master, text="漏扫报告html文件夹路径（必填）").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.html_path = ttk.Entry(self.master, width=50)
        self.html_path.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.master, text="浏览", command=lambda: self.browse_folder(self.html_path)).grid(row=0, column=2, padx=5, pady=5)

        # Table Type
        ttk.Label(self.master, text="表格类型").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.table_type = ttk.Combobox(self.master, values=["YPG", "DJCP", "DJCP_MINI", "YPG_MINI", "DEV_PORT"])
        self.table_type.set("DJCP")
        self.table_type.grid(row=1, column=1, padx=5, pady=5)

        # Scanner Type
        ttk.Label(self.master, text="扫描器类型（默认自动选择）").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.scanner_type = ttk.Combobox(self.master, values=["RSAS", "XLSX", "WANGSHEN", "NSFOCUS", "GREEN_LEAGUE", "AUTO"])
        self.scanner_type.set("AUTO")
        self.scanner_type.grid(row=2, column=1, padx=5, pady=5)

        # XLSX Path
        ttk.Label(self.master, text="漏扫目标信息Excel表路径（仅YPG需要）").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.xlsx_path = ttk.Entry(self.master, width=50)
        self.xlsx_path.grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(self.master, text="浏览", command=lambda: self.browse_file(self.xlsx_path, [("Excel Files", "*.xlsx")])).grid(row=3, column=2, padx=5, pady=5)

        # Output Path
        ttk.Label(self.master, text="Word格式报告输出路径及前缀").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.output_path = ttk.Entry(self.master, width=50)
        self.output_path.insert(0, "./转格式")
        self.output_path.grid(row=4, column=1, padx=5, pady=5)
        ttk.Button(self.master, text="浏览", command=lambda: self.browse_file(self.output_path, [("Word Document", "*.docx")], save=True)).grid(row=4, column=2, padx=5, pady=5)

        # Recursive
        self.recursive = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.master, text="递归读取子文件夹下所有ip.html", variable=self.recursive).grid(row=5, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        # Quiet Mode
        self.quiet = tk.BooleanVar()
        ttk.Checkbutton(self.master, text="安静模式", variable=self.quiet).grid(row=6, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        # Suspicious Mode
        self.suspicious = tk.BooleanVar()
        ttk.Checkbutton(self.master, text="SUS", variable=self.suspicious).grid(row=6, column=2, columnspan=2, sticky="w", padx=5, pady=5)

        # Target Path
        ttk.Label(self.master, text="漏扫目标表格输出路径（仅DEV_PORT需要）").grid(row=7, column=0, sticky="w", padx=5, pady=5)
        self.target_path = ttk.Entry(self.master, width=50)
        self.target_path.grid(row=7, column=1, padx=5, pady=5)
        ttk.Button(self.master, text="浏览", command=lambda: self.browse_file(self.target_path, [("Excel Files", "*.xlsx")], save=True)).grid(row=7, column=2, padx=5, pady=5)

        # Limit Result
        ttk.Label(self.master, text="限制每个漏洞的IP数量（-1不限制）").grid(row=8, column=0, sticky="w", padx=5, pady=5)
        self.limit_result = ttk.Entry(self.master, width=50)
        self.limit_result.insert(0, "-1")
        self.limit_result.grid(row=8, column=1, padx=5, pady=5)

        # Run and Exit Buttons
        ttk.Button(self.master, text="运行", command=self.run).grid(row=9, column=0, padx=5, pady=5)
        ttk.Button(self.master, text="退出", command=self.master.quit).grid(row=9, column=1, padx=5, pady=5)

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

            table_type_mapping = {
                "YPG": TableType.YPG,
                "DJCP": TableType.DJCP,
                "DJCP_MINI": TableType.DJCP_MINI,
                "YPG_MINI": TableType.YPG_MINI,
                "DEV_PORT": TableType.DEV_PORT,
            }
            prime.set_table_type(table_type_mapping[self.table_type.get()])

            scanner_type_mapping = {
                "RSAS": ScannerType.RSAS,
                "XLSX": ScannerType.XLSX,
                "WANGSHEN": ScannerType.WANGSHEN,
                "NSFOCUS": ScannerType.NSFOCUS,
                "GREEN_LEAGUE": ScannerType.GREEN_LEAGUE,
                "AUTO": ScannerType.AUTO
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
    VulnerabilityScanReportGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()