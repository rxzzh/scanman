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
