import PySimpleGUI as sg
from scanman.core import Prime, ScannerType, TableType

def create_window():
    layout = [
        [sg.Text("漏扫报告html文件夹路径（必填）"), sg.Input(key="-HTML_PATH-"), sg.FolderBrowse()],
        [sg.Text("表格类型"), sg.Combo(["YPG", "DJCP", "DJCP_MINI", "YPG_MINI", "DEV_PORT"], default_value="DJCP", key="-TABLE_TYPE-")],
        [sg.Text("扫描器类型"), sg.Combo(["RSAS", "XLSX", "WANGSHEN"], default_value="RSAS", key="-SCANNER_TYPE-")],
        [sg.Text("漏扫目标信息Excel表路径（仅YPG需要）"), sg.Input(key="-XLSX_PATH-"), sg.FileBrowse()],
        [sg.Text("Word格式报告输出路径及前缀"), sg.Input(default_text="./转格式输出", key="-OUTPUT_PATH-"), sg.FileSaveAs()],
        [sg.Checkbox("递归读取子文件夹下所有ip.html", default=True, key="-RECURSIVE-")],
        [sg.Checkbox("安静模式", key="-QUIET-")],
        [sg.Text("漏扫目标表格输出路径"), sg.Input(key="-TARGET-"), sg.FileSaveAs()],
        [sg.Text("限制每个漏洞的IP数量（-1不限制）"), sg.Input(default_text="-1", key="-LIMIT_RESULT-")],
        [sg.Button("运行"), sg.Button("退出")]
    ]

    return sg.Window("漏洞扫描报告生成器 by rxzzh", layout)

def run_prime(values):
    if not values["-HTML_PATH-"]:
        raise ValueError("漏扫报告html文件夹路径不能为空")

    prime = Prime()
    prime.set_html_path(values["-HTML_PATH-"])
    prime.set_xlsx_path(values["-XLSX_PATH-"])
    prime.set_output_full_path(values["-OUTPUT_PATH-"])
    prime.set_recursive_read(values["-RECURSIVE-"])
    prime.set_target(values["-TARGET-"])
    prime.set_limit_result_amount(limit=int(values["-LIMIT_RESULT-"]))

    table_type_mapping = {
        "YPG": TableType.YPG,
        "DJCP": TableType.DJCP,
        "DJCP_MINI": TableType.DJCP_MINI,
        "YPG_MINI": TableType.YPG_MINI,
        "DEV_PORT": TableType.DEV_PORT,
    }
    prime.set_table_type(table_type_mapping[values["-TABLE_TYPE-"]])

    scanner_type_mapping = {
        "RSAS": ScannerType.RSAS,
        "XLSX": ScannerType.XLSX,
        "WANGSHEN": ScannerType.WANGSHEN
    }
    prime.set_scanner_type(scanner_type_mapping[values["-SCANNER_TYPE-"]])
    prime.set_quiet(quiet=values["-QUIET-"])

    prime.go()

def main():
    window = create_window()

    while True:
        event, values = window.read()
        if event == sg.WINDOW_CLOSED or event == "退出":
            break
        if event == "运行":
            try:
                run_prime(values)
                output_path = values["-OUTPUT_PATH-"]
                target_path = values["-TARGET-"]
                completion_message = f"处理完成！\n\nWord格式报告已输出到：{output_path}"
                if target_path:
                    completion_message += f"\n\n漏扫目标表格已输出到：{target_path}"
                sg.popup(completion_message, title="成功")
            except ValueError as ve:
                sg.popup_error(str(ve), title="错误")
            except Exception as e:
                sg.popup_error(f"发生错误：{str(e)}\n路径下是否包含x.x.x.x.html的漏扫报告？", title="错误")

    window.close()

if __name__ == "__main__":
    main()