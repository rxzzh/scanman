from email.policy import default
from .utils import html_names_of_path
from .read import RSASParser, XLSXParser
from rich import print as pprint
from .build import build_table

class Prime:
  def __init__(self) -> None:
    self.html_path = "project/ahyd/hosts/"
    self.xlsx_path = "project/ahyd/targets_xlsx/properties.xlsx"
    self.output_full_path = "./out.docx"
    self.parser = RSASParser()
    self.xlsx_parser = XLSXParser()
    self.hosts = []
    self.vulnerabilities = []
    self.affections = {}

  def set_html_path(self, path):
    self.html_path=path
  
  def set_xlsx_path(self, path):
    self.xlsx_path=path

  def set_output_full_path(self, full_path):
    self.output_full_path=full_path

  def run(self):
    self.read_vulnerabilities_from_html()
    self.read_hosts_from_html()
    self.read_hosts_names_from_xlsx()
    self.read_affections_from_html()
    self.padding_empty_fields()
    self.build()

  def build(self):
    build_table(
      vulnerabilities=self.vulnerabilities,
      hosts=self.hosts,
      affections=self.affections,
      filename=self.output_full_path
    )


  def read_vulnerabilities_from_html(self):
    filenames = html_names_of_path(self.html_path)
    for name in filenames:
      new_vuls = self.parser.parse_vulnerability(open(self.html_path+name).read())
      for vul in new_vuls:
        if vul not in self.vulnerabilities:
          self.vulnerabilities.append(vul)
    pprint(self.vulnerabilities)

  def read_hosts_from_html(self):
    filenames = html_names_of_path(self.html_path)
    for name in filenames:
      new_host = self.parser.parse_host(open(self.html_path+name).read())[0]
      if new_host not in self.hosts:
        new_host.name = "主机"+new_host.ip
        self.hosts.append(new_host)

  def read_hosts_names_from_xlsx(self):
    if self.xlsx_path == "":
      return
    res = self.xlsx_parser.read_host_name_ip(path=self.xlsx_path)
    for host in self.hosts:
      if host.ip in res:
        host.name = res[host.ip]

  def read_affections_from_html(self):
    filenames = html_names_of_path(self.html_path)
    for name in filenames:
      host, affections = self.parser.parse_host(open(self.html_path+name).read())
      for vul in affections:
        if vul not in self.affections:
          self.affections[vul] = []
        self.affections[vul].append(host.ip)
  
  def padding_empty_fields(self):
    for vul in self.vulnerabilities:
      if vul.solution == "":
        vul.solution = "暂无漏洞修复建议。"
      if vul.description == "":
        vul.description = "暂无漏洞详细描述。"

# if __name__ == "__main__":
#   p = Prime()
#   p.read_vulnerabilities_from_html()
#   p.read_hosts_from_html()
#   p.read_affections_from_html()
#   p.read_hosts_names_from_xlsx()
#   pprint(p.vulnerabilities, p.hosts)
#   p.build()