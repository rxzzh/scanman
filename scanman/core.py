from .utils import html_names_of_path, recursive_html_names_of_path, recursive_xlsx_names_of_path
from .read import RSASParser, XLSXParser, TRXParser, XLSXReportParser, WANGSHENParser, XLSXSelectiveRemoveParser
from .build import build_table, build_table_djcp, build_table_djcp_mini, build_table_ypg_mini, build_table_djcp_summary, build_table_target, build_port_xlsx
from tqdm import tqdm
import plotext as plt
from tabulate import tabulate
from rich import print as rprint

class TableType:
  YPG = 0
  DJCP = 1
  DJCP_MINI = 2
  YPG_MINI = 3
  DEV_PORT = 4


class ScannerType:
  RSAS = 0
  TRX = 1
  NESSUS = 2
  XLSX = 3
  WANGSHEN = 4


class Prime:
  def __init__(self) -> None:
    self.html_path = None
    self.xlsx_path = None
    self.output_full_path = None
    self.parser = None
    self.xlsx_parser = XLSXParser()
    self.hosts = []
    self.vulnerabilities = []
    self.affections = {}
    self.table_type = None
    self.scanner_type = None
    self.recursive_read = False
    self.feed_html_path = html_names_of_path
    self.quiet = False
    self.suspicious = False
    self.target_table_path = ''
    self.reuslt_amount = -1 
    self.selective_remove_path = None
  
  def go(self):
    if self.scanner_type == ScannerType.XLSX:
      self.run_xlsx_like()
    else:
      self.run()

  def set_suspicious(self, suspicious):
    self.suspicious = suspicious

  def set_html_path(self, path):
    self.html_path = path

  def set_xlsx_path(self, path):
    self.xlsx_path = path

  def set_output_full_path(self, full_path):
    self.output_full_path = full_path

  def set_table_type(self, table_type):
    self.table_type = table_type

  def set_scanner_type(self, scanner_type):
    self.scanner_type = scanner_type
  
  def set_recursive_read(self, recursive):
    self.recursive_read = recursive
    if recursive:
      self.feed_html_path = recursive_html_names_of_path
  
  def set_quiet(self, quiet):
    self.quiet = quiet
  
  def set_target(self, target):
    self.target_table_path = target
  
  def set_limit_result_amount(self, limit):
    self.reuslt_amount = limit
  
  def set_selective_remove(self, path):
    self.selective_remove_path = path

  def run(self):
    if self.scanner_type == ScannerType.RSAS:
      self.parser = RSASParser()
    if self.scanner_type == ScannerType.TRX:
      self.parser = TRXParser()
    if self.scanner_type == ScannerType.WANGSHEN:
      self.parser = WANGSHENParser()

    self.read_vulnerabilities_from_html()
    self.read_hosts_from_html()
    self.read_hosts_names_from_xlsx()
    self.read_affections_from_html()
    self.selective_remove_vulns()
    if self.reuslt_amount > -1:
      self.limit_reuslt_amount(max_ip_for_vulnerability=self.reuslt_amount)
    if self.suspicious:
      self.suspicious_get_rid()
    self.padding_empty_fields()
    if not self.quiet:
      self.summary()
    self.build()

  def build(self):
    if self.table_type == TableType.YPG:
      build_table(
          vulnerabilities=self.vulnerabilities,
          hosts=self.hosts,
          affections=self.affections,
          filename=self.output_full_path
      )
    if self.table_type == TableType.DJCP:
      build_table_djcp(
          vulnerabilities=self.vulnerabilities,
          hosts=self.hosts,
          affections=self.affections,
          filename=self.output_full_path
      )
      build_table_djcp_summary(
        vulnerabilities=self.vulnerabilities,
        hosts=self.hosts,
        affections=self.affections,
        filename=self.output_full_path
      )
    if self.table_type == TableType.DJCP_MINI:
      build_table_djcp_mini(
        vulnerabilities=self.vulnerabilities,
        hosts=self.hosts,
        affections=self.affections,
        filename=self.output_full_path
      )
    if self.table_type == TableType.YPG_MINI:
      build_table_ypg_mini(
        vulnerabilities=self.vulnerabilities,
        hosts=self.hosts,
        affections=self.affections,
        filename=self.output_full_path
      )
    if self.table_type == TableType.DEV_PORT:
      build_port_xlsx(
        hosts=self.hosts
      )
    if self.target_table_path:
      build_table_target(
        hosts=self.hosts,
        filename=self.target_table_path
      )
      

  def read_vulnerabilities_from_html(self):
    filenames = self.feed_html_path(self.html_path)
    for name in tqdm(filenames):
      with open(name, 'rb') as f:
        text = f.read()
      new_vuls = self.parser.parse_vulnerability(text)
      for vul in new_vuls:
        if vul not in self.vulnerabilities:
          self.vulnerabilities.append(vul)

  def read_hosts_from_html(self):
    filenames = self.feed_html_path(self.html_path)
    for name in tqdm(filenames):
      with open(name, 'rb') as f:
        text = f.read()
      new_host = self.parser.parse_host(text)[0]
      if new_host not in self.hosts:
        self.hosts.append(new_host)

  def read_affections_from_html(self):
    filenames = self.feed_html_path(self.html_path)
    for name in tqdm(filenames):
      with open(name, 'rb') as f:
        text = f.read()
      host, affections = self.parser.parse_host(text)
      for vul in affections:
        if vul not in self.affections:
          self.affections[vul] = []
        self.affections[vul].append(host.ip)

  def read_hosts_names_from_xlsx(self):
    if self.xlsx_path == "":
      return
    res = self.xlsx_parser.read_host_name_ip(path=self.xlsx_path)
    for host in tqdm(self.hosts):
      if host.ip in res:
        host.name = res[host.ip]

  def padding_empty_fields(self):
    for vul in self.vulnerabilities:
      if vul.solution == "":
        vul.solution = "暂无漏洞修复建议。"
      if vul.description == "":
        vul.description = "暂无漏洞详细描述。"
    for host in self.hosts:
      if not host.name:
        host.name = "主机"+host.ip


  def summary(self):
      total_count = len(self.vulnerabilities)
      high_count = len(list(filter(lambda x: x.severity == "high", self.vulnerabilities)))
      middle_count = len(list(filter(lambda x: x.severity == "middle", self.vulnerabilities)))
      low_count = len(list(filter(lambda x: x.severity == "low", self.vulnerabilities)))

      # 使用tabulate打印高危、中危、低危、全部漏洞数量
      rprint("\n漏洞总体统计：")
      vulnerability_summary = [
          ["低危", low_count],
          ["中危", middle_count],
          ["高危", high_count],
          ["总数", total_count]
      ]
      rprint(tabulate(vulnerability_summary, headers=["漏洞级别", "数量"], tablefmt="pretty", colalign=("left", "right")))

      rprint("\n漏洞总体统计图：")
      plt.clear_figure()
      plt.bar(["低危", "中危", "高危", "总数"], [low_count, middle_count, high_count, total_count], color="red")
      plt.title("漏洞总体统计")
      plt.show()

      host_vul_count = {}
      vulnerability_map = {}
      for vul in self.vulnerabilities:
          vulnerability_map[vul.name] = vul
      for affection in self.affections:
          hosts = self.affections[affection]
          severity = vulnerability_map[affection].severity
          for host in hosts:
              if host not in host_vul_count:
                  host_vul_count[host] = {'low': 0, 'middle': 0, 'high': 0}
              host_vul_count[host][severity] += 1
      
      highest = 0
      for count in host_vul_count:
          if host_vul_count[count]['high'] > highest:
              highest = host_vul_count[count]['high']
      high_count = [0] * (highest+1)
      for count in host_vul_count:
          high_count[host_vul_count[count]['high']] += 1

      rprint("\n高危漏洞数量分布：")

      # 准备数据
      x = [str(i) for i in range(len(high_count))]
      y = high_count

      # 创建图表
      plt.clear_figure()
      plt.bar(x, y)
      plt.title("高危漏洞-主机数量分布")
      plt.xlabel("高危漏洞数量")
      plt.ylabel("主机数量")
      plt.show()

      rprint("横坐标：高危漏洞数量")
      rprint("纵坐标：对应的主机数量\n")

      # 使用plotext打印漏洞-主机表
      rprint("\n漏洞数量分布：")
      vuln_count_distribution = {}
      for host, counts in host_vul_count.items():
          total_vulns = sum(counts.values())
          if total_vulns not in vuln_count_distribution:
              vuln_count_distribution[total_vulns] = 0
          vuln_count_distribution[total_vulns] += 1

      x = list(vuln_count_distribution.keys())
      y = list(vuln_count_distribution.values())
      plt.clear_figure()
      plt.bar(x, y)
      plt.title("漏洞-主机数量分布")
      plt.xlabel("漏洞数量")
      plt.ylabel("主机数量")
      plt.show()

      rprint("横坐标：漏洞数量（总数，不区分高中低）")
      rprint("纵坐标：对应主机数量\n")

      # 表格形式输出
      col_0 = range(len(high_count))
      col_1 = high_count
      rprint("\n高危漏洞数量分布（表格形式）：")
      table_data = [[col_0[i], col_1[i]] for i in range(len(high_count))]
      table_data = list(filter(lambda x: x[1]>0, table_data))
      rprint(tabulate(table_data, 
                    headers=['高危数', '主机数'], 
                    tablefmt="pretty"))





      # 受影响主机Top 20
      host_total_vulns = {host: sum(counts.values()) for host, counts in host_vul_count.items()}
      top_20_hosts = sorted(host_total_vulns.items(), key=lambda x: x[1], reverse=True)[:20]
      
      rprint("\n受影响主机Top 20：")
      headers = ["主机", "漏洞数"]
      rprint(tabulate(top_20_hosts, headers=headers, tablefmt="pretty", colalign=("left", "right")))

      # 添加0漏洞IP表格
      zero_vuln_ips = [host for host, total_vulns in host_total_vulns.items() if total_vulns == 0]
      
      if zero_vuln_ips:
          rprint("\n0漏洞IP：")
          # 将IP地址分成多列显示，每列最多显示20个IP
          columns = 4
          rows = -(-len(zero_vuln_ips) // columns)  # 向上取整
          ip_table = []
          for i in range(rows):
              row = zero_vuln_ips[i::rows]
              row += [''] * (columns - len(row))  # 填充空字符串以保持列数一致
              ip_table.append(row)
          
          headers = [f"Column {i+1}" for i in range(columns)]
          rprint(tabulate(ip_table, headers=headers, tablefmt="pretty"))
          rprint(f"\n总计: {len(zero_vuln_ips)} 个0漏洞IP")
      else:
          # rprint("\n没有0漏洞的IP地址。")
          pass

  
  def run_xlsx_like(self):
    parser = XLSXReportParser()
    for filename in tqdm(recursive_xlsx_names_of_path(self.html_path)):
      vuls, hosts, affections = parser.parse(path=filename)
      for vul in vuls:
        if vul not in self.vulnerabilities:
          self.vulnerabilities.append(vul)
      for host in hosts:
        if host not in self.hosts:
          self.hosts.append(host)
      for affection in affections:
        if affection not in self.affections:
          self.affections[affection] = []
        self.affections[affection].extend(affections[affection])
    self.build()
  
  def suspicious_get_rid(self):
    # clean_vuls = list(filter(lambda x: x.severity=="low" and "CVE" not in x.name, self.vulnerabilities))
    clean_vuls = list(filter(lambda x: x.severity!="high", self.vulnerabilities))
    self.vulnerabilities = clean_vuls
    vuln_names = [_.name for _ in self.vulnerabilities]
    clean_affections = {}
    for name in self.affections:
      if name in vuln_names:
        clean_affections[name] = self.affections[name]
    self.affections = clean_affections
    
  def limit_reuslt_amount(self, max_ip_for_vulnerability):
    for affection in self.affections:
      affection_count = len(self.affections[affection])
      self.affections[affection] = self.affections[affection][:max_ip_for_vulnerability]
      self.affections[affection].append("等共{}个IP地址".format(affection_count))
      # print(self.affections[affection])

  def selective_remove_vulns(self):
    if not self.selective_remove_path:
      return
    remove_tuples = XLSXSelectiveRemoveParser.function_parse(path=self.selective_remove_path)
    print('[INFO]读取到{}条“漏洞-IP”整改记录'.format(len(remove_tuples)))
    count = 0
    for tuple in remove_tuples:
      vuln_name = tuple[0]
      ip = tuple[1]
      if vuln_name in self.affections and ip in self.affections[vuln_name]:
        self.affections[vuln_name].remove(ip)
        if len(self.affections[vuln_name]) == 0:
          del self.affections[vuln_name]
          self.vulnerabilities.remove(vuln_name)
        count += 1
    print('[INFO]已修正{}个IP'.format(count))
    
    

if __name__ == "__main__":
  prime = Prime()
  prime.run_xlsx_like()
