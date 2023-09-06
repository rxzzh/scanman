from .utils import html_names_of_path, recursive_html_names_of_path, recursive_xlsx_names_of_path
from .read import RSASParser, XLSXParser, TRXParser, XLSXReportParser, WANGSHENParser
from .build import build_table, build_table_djcp, build_table_djcp_mini, build_table_ypg_mini, build_table_djcp_summary, build_table_target
from tqdm import tqdm
from tabulate import tabulate

class TableType:
  YPG = 0
  DJCP = 1
  DJCP_MINI = 2
  YPG_MINI = 3


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
    self.padding_empty_fields()
    if self.suspicious:
      self.suspicious_get_rid()
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
    high_count = len(
        list(filter(lambda x: x.severity == "high", self.vulnerabilities)))
    middle_count = len(
        list(filter(lambda x: x.severity == "middle", self.vulnerabilities)))
    low_count = len(
        list(filter(lambda x: x.severity == "low", self.vulnerabilities)))

    print(tabulate([[low_count, middle_count, high_count, total_count]], headers=[
          '低危', '中危', '高危', '总数'], tablefmt="psql"))

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

    col_0 = range(len(high_count))
    col_1 = high_count

    print(tabulate([[col_0[i], col_1[i]] for i in range(
        len(high_count))], headers=['高危数', '主机数'], tablefmt="psql"))
  
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
    

if __name__ == "__main__":
  prime = Prime()
  prime.run_xlsx_like()
