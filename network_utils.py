from scapy.all import Ether, ARP, srp, conf
import platform
import subprocess
import atexit
import os

devices = []


# --- scan sítě --- #
def scan_network():
    ip_addr = input("[?] IP rozsah (např. 192.168.1.1/24): ")

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_addr)

    print(f"\n[*] scan {ip_addr}\n")

    result = srp(packet, timeout=3, verbose=0)[0]

    if not result:
        print("[-] nic")
        return

    devices.clear()

    for i, (s, r) in enumerate(result, start=1):
        devices.append({"ip": r.psrc, "mac": r.hwsrc})
        print(f"{i}. {r.psrc} | {r.hwsrc}")


# --- výběr cíle --- #
def select_target():
    if not devices:
        print("[-] nejdřív scan")
        return None, None

    while True:
        choice = input("\nčíslo cíle nebo r (router): ").strip()

        if choice.lower() == "r":
            router_ip = conf.route.route("0.0.0.0/0")[2]

            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip)
            ans = srp(packet, timeout=3, verbose=0)[0]

            if ans:
                router_mac = ans[0][1].hwsrc
                return router_ip, router_mac

            print("[-] router nenalezen")
            continue

        try:
            idx = int(choice) - 1
            target = devices[idx]
            return target["ip"], target["mac"]
        except:
            print("[-] špatně")


# --- router info --- #
def get_router():
    router_ip = conf.route.route("0.0.0.0/0")[2]

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip)
    ans = srp(packet, timeout=3, verbose=0)[0]

    if ans:
        router_mac = ans[0][1].hwsrc
        return router_ip, router_mac

    return None, None


# --- ip forwarding --- #
def toggle_forwarding(enable=True):
    system = platform.system()

    if system == "Linux":
        os.system(f"sudo sysctl -w net.ipv4.ip_forward={1 if enable else 0}")

    elif system == "Windows":
        value = "Enabled" if enable else "Disabled"

        subprocess.run(
            ["powershell", "-Command", f"Set-NetIPInterface -Forwarding {value}"],
            capture_output=True
        )


# --- cleanup --- #
def cleanup():
    toggle_forwarding(False)


atexit.register(cleanup)