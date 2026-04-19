import platform
import subprocess
from dataclasses import dataclass

import typer
from beartype import beartype
from scapy.all import ARP, Ether, conf, srp

from const import Packets


def toggle_forwarding(enable: bool) -> None:
    """Enable or disable IP forwarding based on the current OS."""
    system = platform.system()
    match system:
        case "Linux":
            subprocess.run(
                ["sysctl", "-w", f"net.ipv4.ip_forward={'1' if enable else '0'}"],
                check=True,
            )
        case "Windows":
            subprocess.run(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "set",
                    "global",
                    f"forwarding={'enabled' if enable else 'disabled'}",
                ],
                check=True,
            )
        case _:
            typer.echo("[-] Unknown OS. Cannot configure IP forwarding.", err=True)


def scan_network(arp_attack_address: str) -> list[dict]:
    """Scan the network and return a list of discovered devices."""
    devices = []
    packet = Packets.BROADCAST / ARP(pdst=arp_attack_address)
    result = srp(packet, timeout=3, verbose=0)[0]
    for _, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices


def get_gateway_mac() -> str | None:
    """Resolve the MAC address of the default gateway."""
    router_ip = conf.route.route("0.0.0.0/0")[2]
    answered_list = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip), timeout=3, verbose=0
    )[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    return None


@dataclass
class SelectTargetParams:
    choice: str
    devices: list[dict]


@beartype
def get_target(params: SelectTargetParams) -> tuple[str, str]:
    """Return (ip, mac) of the selected target from the device list."""
    try:
        index = int(params.choice) - 1
        if not 0 <= index < len(params.devices):
            raise IndexError
        target = params.devices[index]
        return target["ip"], target["mac"]
    except (ValueError, IndexError) as e:
        raise ValueError("Invalid selection. Please try again.") from e
