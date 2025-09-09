#!/usr/bin/python3

import click
from scanman.core import Prime, ScannerType, TableType


@click.command()
@click.option('-b', '--html_path', required=True, help="漏扫报告html文件夹路径")
@click.option('-t', '--table_type', default="DJCP", type=click.Choice(["YPG", "DJCP","DJCP_MINI","YPG_MINI","DEV_PORT"]), show_default=True, help="选择云评估格式或等级测评格式导出")
@click.option('-s', '--scanner_type', default="AUTO", type=click.Choice(["RSAS", "XLSX", "WANGSHEN", "NSFOCUS", "GREEN_LEAGUE", "AUTO"]), show_default=True, help="所使用的漏洞扫描器类型，AUTO为自动检测模式")
@click.option('-x', '--xlsx_path', default='', help='漏扫目标信息的Excel表路径，表头必须包含ip和name字段')
@click.option('-o', '--output_path', default='./out.docx', help='Word格式报告输出全路径')
@click.option('-r', '--recursive/--no-recursive',  default=False, show_default=True, help="从html文件夹路径下递归地读取命名符合ip.html的文件")
@click.option('-q', '--quiet/--no-quiet', default=False, show_default=True, help="安静模式")
@click.option('-g', '--target', default='', help='输出漏扫目标表格的路径，留空则不输出')
@click.option('-sus', '--suspicious/--no-suspicious', default=False, help="suspicious")
@click.option('-lr','--limit_result_amount', default=-1, help="限制最终报告中每个漏洞的IP数量")
@click.option('-sr', '--selective_remove', default=None, help="选择性去除漏洞，读取xlsx文件，必须包含vuln_name，ip字段，每条记录代表删除一条漏洞记录。ip为“-”则删除所有相关ip")
def cli(html_path, xlsx_path, output_path, table_type, scanner_type, recursive, quiet, suspicious, target, limit_result_amount, selective_remove):
  prime = Prime()
  prime.set_html_path(html_path)
  prime.set_xlsx_path(xlsx_path)
  prime.set_output_full_path(output_path)
  prime.set_recursive_read(recursive)
  prime.set_suspicious(suspicious)
  prime.set_target(target)
  prime.set_limit_result_amount(limit=limit_result_amount)
  prime.set_selective_remove(path=selective_remove)

  table_type_mapping = {
      "YPG": TableType.YPG,
      "DJCP": TableType.DJCP,
      "DJCP_MINI": TableType.DJCP_MINI,
      "YPG_MINI": TableType.YPG_MINI,
      "DEV_PORT": TableType.DEV_PORT,
  }
  prime.set_table_type(table_type_mapping[table_type])

  scanner_type_mapping = {
      "RSAS": ScannerType.RSAS,
      "TRX": ScannerType.TRX,
      "NESSUS": ScannerType.NESSUS,
      "XLSX": ScannerType.XLSX,
      "WANGSHEN": ScannerType.WANGSHEN,
      "NSFOCUS": ScannerType.NSFOCUS,
      "GREEN_LEAGUE": ScannerType.GREEN_LEAGUE,
      "AUTO": ScannerType.AUTO
  }
  prime.set_scanner_type(scanner_type_mapping[scanner_type])
  prime.set_quiet(quiet=quiet)

  prime.go()


if __name__ == "__main__":
  cli()
