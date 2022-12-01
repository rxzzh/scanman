from docx import Document
from .utils import gadget_fill_cell, gadget_fill_cell_super, gadget_set_row_height
from tqdm import tqdm
from rich import print as print


class DocHandler:
  def __init__(self):
    pass

  def build_doc_tablelike(self, records, template_path, filename):
    doc = Document(template_path)
    table = doc.tables[0]
    ROWS = len(records)
    HEAD_ROWS = len(table.rows)
    for i in range(ROWS):
      new_row = table.add_row()
    gadget_set_row_height(rows=table.rows[HEAD_ROWS:])
    COLUMNS = len(new_row.cells)
    cells = table._cells
    cells = cells[HEAD_ROWS*COLUMNS:]
    for i in range(len(records)):
      gadget_fill_cell_super(
          cells=cells[i*COLUMNS:(i+1)*COLUMNS], fields=records[i])
    doc.save(filename)

doc_handler = DocHandler()

def prefix_id(records):
  i = 1
  ret = []
  for _ in records:
    _.insert(0, str(i))
    ret.append(_)
    i += 1
  return ret


num_map = {'low': 0, 'middle': 1, 'high': 2, 'critical': 3}
zh_map = {'low': '低', 'middle': '中', 'high': '高', 'critical':'危急'}


def build_table(vulnerabilities: list, hosts: list, affections: dict, filename="./out.docx"):
  print("building...")
  vulnerabilities.sort(key=lambda x: num_map[x.severity],reverse=True)
  hashtable_ip2host = {}
  for host in hosts:
    hashtable_ip2host[host.ip] = host
  records = []
  for vul in vulnerabilities:
    record = []
    record.append(vul.name)
    record.append(vul.description)
    record.append(zh_map[vul.severity])
    record.append('\n'.join([hashtable_ip2host[_].name for _ in affections[vul.name]]))
    record.append('\n'.join(affections[vul.name]))
    record.append(vul.solution)
    record.append("未整改")
    records.append(record)
  records = prefix_id(records)
  doc_handler.build_doc_tablelike(records=records, template_path="static/template-vulnlist-v2.docx", filename=filename)
  print("done!")

def build_table_djcp(vulnerabilities: list, hosts: list, affections: dict, filename="./out.docx"):
  vulnerabilities.sort(key=lambda x: num_map[x.severity], reverse=True)
  records = []
  for vul in vulnerabilities:
    record = []
    record.append(vul.name)
    record.append(', '.join(affections[vul.name]))
    record.append(zh_map[vul.severity])
    records.append(record)
  records = prefix_id(records)
  doc_handler.build_doc_tablelike(
    records=records,
    template_path="static/template-vulnlist.docx",
    filename=filename
  )

def build_table_djcp_summary(vulnerabilities: list, hosts: list, affections: dict, filename="./out.docx"):
  filename = filename + "_summary.docx"
  
  reversed_affections = {}
  for vul_name in list(affections):
    related_hosts = affections[vul_name]
    for host in related_hosts:
      if host not in reversed_affections:
        reversed_affections[host] = []
      reversed_affections[host].append(vul_name)
  
  records = []

  vulmap = {}
  for vul in vulnerabilities:
    vulmap[vul.name] = vul
  vulnerabilities = vulmap

  sum_low = 0
  sum_middle = 0
  sum_high = 0

  for host in [_.ip for _ in hosts]:
    try:
      vul_names = reversed_affections[host]
    except:
      vul_names = []
    vul_impacts = [vulnerabilities[name].severity for name in vul_names]
    
    
    
    count_low = len(list(filter(lambda x: x=='low', vul_impacts)))
    count_middle = len(list(filter(lambda x: x=='middle', vul_impacts)))
    count_high = len(list(filter(lambda x: x=='high', vul_impacts)))
    
    records.append([host, count_high, count_middle, count_low, count_high+count_middle+count_low])
    sum_low+=count_low
    sum_middle+=count_middle
    sum_high+=count_high
  records.append(['漏洞数量合计',sum_high,sum_middle,sum_low,sum_high+sum_middle+sum_low])
  records = prefix_id(records)
  records[-1][0] = ""
  doc_handler.build_doc_tablelike(
    records=records,
    template_path="static/template-subtotal.docx",
    filename=filename
  )

    

def build_table_djcp_mini(vulnerabilities: list, hosts: list, affections: dict, filename="./out.docx"):
  vulnerabilities.sort(key=lambda x: num_map[x.severity], reverse=True)
  records = []
  for vul in vulnerabilities:
    record = []
    record.append(vul.name)
    record.append(len(affections[vul.name]))
    record.append(zh_map[vul.severity])
    records.append(record)
  records = prefix_id(records)
  doc_handler.build_doc_tablelike(
    records=records,
    template_path="static/template-vulnlist-mini.docx",
    filename=filename
  )


def build_table_ypg_mini(vulnerabilities: list, hosts: list, affections: dict, filename="./out.docx"):
  print("building...")
  vulnerabilities.sort(key=lambda x: num_map[x.severity],reverse=True)
  hashtable_ip2host = {}
  for host in hosts:
    hashtable_ip2host[host.ip] = host
  records = []
  for vul in vulnerabilities:
    record = []
    record.append(vul.name)
    record.append(vul.description)
    record.append(zh_map[vul.severity])
    record.append('/')
    record.append(len(affections[vul.name]))
    record.append(vul.solution)
    record.append("未整改")
    records.append(record)
  records = prefix_id(records)
  doc_handler.build_doc_tablelike(records=records, template_path="static/template-vulnlist-v2-mini.docx", filename=filename)
  print("done!")

