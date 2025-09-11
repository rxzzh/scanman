from .utils import html_names_of_path, recursive_html_names_of_path, recursive_xlsx_names_of_path
from .read import RSASParser, XLSXParser, TRXParser, XLSXReportParser, WANGSHENParser, XLSXSelectiveRemoveParser, NSFOCUSParser, GreenLeagueParser
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
  NSFOCUS = 5
  GREEN_LEAGUE = 6
  AUTO = 7  # 自动检测模式


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
    self.filter_enabled = False
    self.filter_rules = {}
  
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

  def set_filter_rules(self, rules):
    self.filter_rules = rules

  def set_filter_enabled(self, enabled: bool):
    self.filter_enabled = enabled

  def auto_detect_parser(self, text):
    """
    自动检测并返回合适的Parser
    
    Args:
        text: HTML文本内容
    
    Returns:
        Parser: 匹配的Parser实例，如果没有匹配则返回None
    """
    # 创建所有可能的Parser实例
    parsers = [
      RSASParser(),
      WANGSHENParser(), 
      NSFOCUSParser(),
      GreenLeagueParser(),
      TRXParser()  # TRX暂时没有实现detect方法，放在最后
    ]
    
    # 尝试每个Parser的detect方法
    for parser in parsers:
      if hasattr(parser, 'detect') and parser.detect(text):
        return parser
    
    return None

  def run(self):
    if self.scanner_type == ScannerType.RSAS:
      self.parser = RSASParser()
    elif self.scanner_type == ScannerType.TRX:
      self.parser = TRXParser()
    elif self.scanner_type == ScannerType.WANGSHEN:
      self.parser = WANGSHENParser()
    elif self.scanner_type == ScannerType.NSFOCUS:
      self.parser = NSFOCUSParser()
    elif self.scanner_type == ScannerType.GREEN_LEAGUE:
      self.parser = GreenLeagueParser()
    elif self.scanner_type == ScannerType.AUTO:
      # 自动模式：不预设parser，在处理文件时动态选择
      self.parser = None
    
    # 根据模式读取数据
    if self.scanner_type == ScannerType.AUTO:
      self.read_vulnerabilities_from_html_auto()
      self.read_hosts_from_html_auto()
      self.read_affections_from_html_auto()
    else:
      self.read_vulnerabilities_from_html()
      self.read_hosts_from_html()
      self.read_affections_from_html()

    self.read_hosts_names_from_xlsx()
    
    # 执行通用的后续处理步骤
    self._process_data()

  def _process_data(self):
    """提取出的通用数据处理流程"""
    if self.filter_enabled and self.filter_rules:
      self.filter_affections(self.filter_rules)
    self.selective_remove_vulns()
    if self.suspicious:
      self.suspicious_get_rid()
    if self.reuslt_amount > -1:
      self.limit_reuslt_amount(max_ip_for_vulnerability=self.reuslt_amount)
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
      build_table_target(
        hosts=self.hosts,
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

  def read_vulnerabilities_from_html_auto(self):
    """自动模式：读取漏洞信息"""
    filenames = self.feed_html_path(self.html_path)
    parser_stats = {}  # 统计各Parser的使用次数
    
    for name in tqdm(filenames):
      with open(name, 'rb') as f:
        text = f.read()
      
      # 自动检测Parser
      parser = self.auto_detect_parser(text)
      if parser is None:
        if not self.quiet:
          print(f"警告：无法识别文件格式: {name}")
        continue
      
      # 统计Parser使用情况
      parser_name = type(parser).__name__
      parser_stats[parser_name] = parser_stats.get(parser_name, 0) + 1
      
      new_vuls = parser.parse_vulnerability(text)
      for vul in new_vuls:
        if vul not in self.vulnerabilities:
          self.vulnerabilities.append(vul)
    
    if not self.quiet and parser_stats:
      print(f"Parser使用统计: {parser_stats}")

  def read_hosts_from_html(self):
    filenames = self.feed_html_path(self.html_path)
    for name in tqdm(filenames):
      with open(name, 'rb') as f:
        text = f.read()
      new_host = self.parser.parse_host(text)[0]
      if new_host not in self.hosts:
        self.hosts.append(new_host)

  def read_hosts_from_html_auto(self):
    """自动模式：读取主机信息"""
    filenames = self.feed_html_path(self.html_path)
    
    for name in tqdm(filenames):
      with open(name, 'rb') as f:
        text = f.read()
      
      # 自动检测Parser
      parser = self.auto_detect_parser(text)
      if parser is None:
        continue
      
      try:
        new_host = parser.parse_host(text)[0]
        if new_host not in self.hosts:
          self.hosts.append(new_host)
      except Exception as e:
        if not self.quiet:
          print(f"警告：解析主机信息失败: {name}, 错误: {e}")

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

  def read_affections_from_html_auto(self):
    """自动模式：读取影响关系"""
    filenames = self.feed_html_path(self.html_path)
    
    for name in tqdm(filenames):
      with open(name, 'rb') as f:
        text = f.read()
      
      # 自动检测Parser
      parser = self.auto_detect_parser(text)
      if parser is None:
        continue
      
      try:
        host, affections = parser.parse_host(text)
        for vul in affections:
          if vul not in self.affections:
            self.affections[vul] = []
          self.affections[vul].append(host.ip)
      except Exception as e:
        if not self.quiet:
          print(f"警告：解析影响关系失败: {name}, 错误: {e}")

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

  def filter_affections(self, rules):
    """
    根据提供的规则过滤 affections 和 vulnerabilities。

    Args:
        rules (dict): 过滤规则的DSL。
    """
    # 创建漏洞名称到对象的映射以便快速查找
    vuln_map = {v.name: v for v in self.vulnerabilities}
    
    # 待删除的漏洞名称
    vulns_to_remove = set()

    for vuln_name, ips in self.affections.items():
      vuln = vuln_map.get(vuln_name)
      if not vuln:
        continue

      # 对每个漏洞的IP列表进行过滤
      filtered_ips = [ip for ip in ips if self._evaluate_rules(rules, vuln, ip)]
      
      if not filtered_ips:
        # 如果过滤后没有IP，则标记该漏洞以便后续删除
        vulns_to_remove.add(vuln_name)
      else:
        # 更新IP列表
        self.affections[vuln_name] = filtered_ips

    # 删除没有关联IP的漏洞
    for vuln_name in vulns_to_remove:
      del self.affections[vuln_name]
    
    # 更新 self.vulnerabilities 列表
    self.vulnerabilities = [v for v in self.vulnerabilities if v.name not in vulns_to_remove]

  def _evaluate_rules(self, rules, vuln, ip):
    """
    递归评估过滤规则。

    Args:
        rules (dict): 规则DSL。
        vuln (Vulnerability): 当前漏洞对象。
        ip (str): 当前IP地址。

    Returns:
        bool: 如果满足规则则返回True，否则返回False。
    """
    logical_operator = rules.get("logical_operator", "AND").upper()
    
    results = []
    for rule in rules.get("rules", []):
      if "logical_operator" in rule:
        # 嵌套规则
        results.append(self._evaluate_rules(rule, vuln, ip))
      else:
        # 基本规则
        results.append(self._check_rule(rule, vuln, ip))

    if logical_operator == "AND":
      return all(results)
    elif logical_operator == "OR":
      return any(results)
    elif logical_operator == "NOT":
      # NOT 操作符只对其后的第一个（也应该是唯一一个）规则生效
      return not results[0] if results else True
    
    return False

  def _check_rule(self, rule, vuln, ip):
    """
    检查单个规则。

    Args:
        rule (dict): 单个规则。
        vuln (Vulnerability): 漏洞对象。
        ip (str): IP地址。

    Returns:
        bool: 规则是否匹配。
    """
    field = rule.get("field")
    operator = rule.get("operator", "equal").lower()
    value = rule.get("value")

    target_value = None
    if field == "ip":
      target_value = ip
    elif hasattr(vuln, field):
      target_value = getattr(vuln, field)
    
    if target_value is None:
      return False

    if operator == "equal":
      return target_value == value
    elif operator == "not equal":
      return target_value != value
    elif operator == "in":
      return target_value in value
    elif operator == "not in":
      return target_value not in value
    elif operator == "contains":
      return isinstance(target_value, str) and value in target_value
    elif operator == "not contains":
      return isinstance(target_value, str) and value not in target_value
      
    return False

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
