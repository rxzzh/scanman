from pydantic import BaseModel

from typing import Optional, List


class Host(BaseModel):
  ip: str
  name: Optional[str]
  ports: Optional[List]

  def __hash__(self) -> int:
    return hash(self.ip)

  def __eq__(self, other) -> bool:
    return True if other.ip == self.ip else False


class Vulnerability(BaseModel):
  name: str
  severity: str
  description: str
  solution: str

  def __hash__(self) -> int:
    return hash(self.name)

  def __eq__(self, other) -> bool:
    if isinstance(other, Vulnerability):
      return True if other.name == self.name else False
    if isinstance(other, str):
      return True if other == self.name else False
