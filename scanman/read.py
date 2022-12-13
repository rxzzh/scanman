from lxml import etree
from .model import Vulnerability, Host
from openpyxl import load_workbook


class Parser:
  def __init__(self) -> None:
    pass

  def clean(self, text: str):
    ret = text
    bad_tokens = ['\n', '\t', ' ']
    for token in bad_tokens:
      ret = ret.replace(token, "")
    return ret

  def parse_vulnerability(self, text):
    pass

  def parse_host(self, text):
    pass


class RSASParser(Parser):
  def parse_vulnerability(self, text):
    root = etree.HTML(text)

    vuln_names = root.xpath(
        '//*[@id="vul_detail"]/table/tr/td/span/text()')
    vuln_names = list(map(str.strip, vuln_names))

    vuln_threat = root.xpath(
        '//*[@id="vul_detail"]/table/tr/td/span/@class')
    vuln_threat = list(map(lambda x: x.split('_')[2], vuln_threat))

    nodes = root.xpath('//*[@class="solution"]/td/table/tr[1]/td')
    vuln_desc = ["".join(node.itertext()) for node in nodes]
    vuln_desc = list(map(self.clean, vuln_desc))

    nodes = root.xpath('//*[@class="solution"]/td/table/tr[2]/td')
    vuln_solution = ["".join(node.itertext()) for node in nodes]
    vuln_solution = list(map(self.clean, vuln_solution))

    fields = [vuln_names, vuln_threat, vuln_solution, vuln_desc]
    assert (any(len(field) == len(fields[0]) for field in fields))

    ret = []

    for i in range(len(vuln_names)):
      ret.append(Vulnerability(
          name=vuln_names[i],
          severity=vuln_threat[i],
          description=vuln_desc[i],
          solution=vuln_solution[i]
      ))
    return ret

  def parse_host(self, text):
    root = etree.HTML(text)

    host_ip = root.xpath(
        '//*[@id="content"]/div[2]/table[2]/tr/td[1]/table/tbody/tr[1]/td/text()')[0]
    vuln_names = root.xpath(
        '//*[@id="vul_detail"]/table/tr/td/span/text()')
    vuln_names = list(map(str.strip, vuln_names))
    return Host(ip=host_ip), vuln_names


class TRXParser(Parser):
  def parse_vulnerability(self, text):
    return super().parse_vulnerability(text)

  def parse_host(self, text):
    return super().parse_host(text)


class XLSXParser:
  def __init__(self) -> None:
    pass

  def read_host_name_ip(self, path):
    wb = load_workbook(path)
    ws = list(wb)[0]
    ip_col = -1
    name_col = -1
    ret = {}
    row = 1
    for col in range(1, 64):
      value = ws.cell(column=col, row=row).value
      if value == 'ip':
        ip_col = col
      if value == 'name':
        name_col = col
    row = 2
    while True:
      if ws.cell(column=ip_col, row=row).value == None:
        break
      ip = ws.cell(column=ip_col, row=row).value
      name = ws.cell(column=name_col, row=row).value
      ret[ip] = name
      row += 1
    return ret

class XLSXReportParser(Parser):
  def parse(self, path):
    wb = load_workbook(path)
    ws = list(wb)[0]
    host_ip_col = 2
    host_name_col = 3
    vulnerability_name_col = 14
    vulnerability_severity_col = 13
    vulnerability_decription_col = 20
    vulnerability_solution_col = 21

    row = 2

    def get_col_value(col):
      return ws.cell(column=col, row=row).value
    
    hosts = []
    vuls = []
    affections = {}

    while True:
      host_name = get_col_value(col=host_name_col)
      host_ip = get_col_value(col=host_ip_col)
      vul_name = get_col_value(col=vulnerability_name_col)
      vul_severity = get_col_value(col=vulnerability_severity_col)
      vul_description = get_col_value(col=vulnerability_decription_col)
      vul_solution = get_col_value(col=vulnerability_solution_col)
      row += 1
      severity_map = {'高危':'high','中危':'middle','低危':'low','危急':'critical'}
      if not host_ip:
        break
      vul = Vulnerability(name=vul_name, severity=severity_map[vul_severity], description=vul_description, solution=vul_solution)
      host = Host(name=host_name, ip=host_ip)

      if vul not in vuls:
        vuls.append(vul)
      if host not in hosts:
        hosts.append(host)
      if vul.name not in affections:
        affections[vul.name] = []
      affections[vul.name].append(host.ip)
    return vuls, hosts, affections


    pass

  def parse_host(self, path):
    pass

class WANGSHENParser(Parser):
  def parse_vulnerability(self, text):
    root = etree.HTML(text)

    name_nodes = root.xpath('//*[@class="odd vuln_middle"]')
    nodes = root.xpath('//*[@class="more hide odd"]')
    
    ret = []

    for i in range(len(nodes)):
      node = nodes[i]
      name = name_nodes[i].xpath('td[1]/span/text()')[0]
      threat = node.xpath('td/table/tr[2]/td/text()')[0][0]
      threat_map = {
        "高":"high",
        "中":"middle",
        "低":"low"
      }
      threat = threat_map[threat]
      desc = node.xpath('td/table/tr[4]/td/text()')[0]
      solution = node.xpath('td/table/tr[5]/td/text()')[0]
      new_vuln = Vulnerability(
        name=name,
        severity = threat,
        description = desc,
        solution=solution
      )
      ret.append(new_vuln)
    return ret

  def parse_host(self, text):
    root = etree.HTML(text)

    host_ip = root.xpath('//*[@class="report_table plumb"]/tbody/tr[2]/td/text()')[0]
    vuln_names = root.xpath('//*[@class="odd vuln_middle"]/td[1]/span/text()')
    return Host(ip=host_ip), vuln_names

  
