import atexit
import os
import platform

from scapy.all import ARP, Ether, conf, srp

# --- Config --- #
ip_addr = input("[?] Zadejte IP adresu včetně prefixu (např. 192.168.1.1/24): ")
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
arp = ARP(pdst=ip_addr)
devices = []

# --- Sken sítě --- #
def scan_network():
    counter = 0
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    for sent, received in result:
        counter += 1
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
        print(f"{counter}. | IP: {received.psrc} | MAC: {received.hwsrc}")

scan_network()


# --- Výběr oběti --- #
def select_target():
    router_ip = conf.route.route("0.0.0.0/0")[2]

    print(f"\n[+] Zjišťuji MAC adresu routeru ({router_ip})...")
    answered_list = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip), timeout=3, verbose=0)[0]

    if answered_list:
        router_mac = answered_list[0][1].hwsrc
        print(f"[+] Router: IP: {router_ip} | MAC: {router_mac}")
    else:
        print(f"[-] Nepodařilo se získat MAC adresu routeru ({router_ip}).")
        return None, None

    while True:
        choice = input("\n[?] Zadejte číslo oběti (nebo 'r' pro router): ").strip()

        if not choice:
            print("[-] Neplatný vstup. Zkuste to znovu.")
            continue

        if choice.lower() == "r":
            return router_ip, router_mac

        try:
            index = int(choice) - 1
            if index < 0:
                raise IndexError

            target = devices[index]
            return target["ip"], target["mac"]
        except (ValueError, IndexError):
            print("[-] Neplatný výběr. Zkuste to znovu.")

select_target()

# --- IP forwarding --- #
def toggle_forwarding(enable=True):
    system = platform.system()

    if system == "Linux":
        value = "1" if enable else "0"
        os.system(f"sysctl -w net.ipv4.ip_forward={value}")

    elif system == "Windows":
        value = "enabled" if enable else "disabled"
        os.system(f"netsh interface ipv4 set global forwarding={value}")

    else:
        print("[-] Neznámý operační systém. Nelze nastavit IP forwarding.")

# --- Cleanup při ukončení --- #
def cleanup():
    print("\n[+] Vypínám IP forwarding...")
    toggle_forwarding(False)

atexit.register(cleanup)

# --- Main --- #
if __name__ == "__main__":
    scan_network()
    print("\n[+] Zapínám IP forwarding...")
    toggle_forwarding(True)
