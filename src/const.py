from dataclasses import dataclass
from typing import ClassVar

from scapy.layers.l2 import Ether


@dataclass
class Packets:
    BROADCAST: ClassVar[Ether] = Ether(dst="ff:ff:ff:ff:ff:ff")
