from dataclasses import dataclass

from beartype import beartype

from network_utils import ether


def scan_network(arp_attack_address: str):
    devices = []
    counter = 0
    packet = ether / ARP(pdst=arp_attack_address)
    result = srp(packet, timeout=3, verbose=0)[0]

    for _, received in result:
        counter += 1
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
        #print(f"{counter}. | IP: {received.psrc} | MAC: {received.hwsrc}")
    return devices


def get_gateway_mac():
    router_ip = conf.route.route("0.0.0.0/0")[2]

    answered_list = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip), timeout=3, verbose=0)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None, None

@dataclass
class SelectTargetParams:
    choice: str
    devices: list[dict]


@beartype
def get_target(params: SelectTargetParams) -> tuple[str, str] | None:
#    if params.choice.lower() == "r":
#        return router_ip, router_mac
    try:
        index = int(params.choice) - 1
        if not 0 <= index < len(params.devices):
            raise IndexError
        target = params.devices[index]
        return target["ip"], target["mac"]
    except (ValueError, IndexError) as e:
        raise ValueError("[-] Neplatný výběr. Zkuste to znovu.") from e
