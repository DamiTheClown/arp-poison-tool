from scapy.all import Ether, ARP, srp, conf
from rich import print
import platform
import subprocess
import atexit
import os

devices = []

print("[red][-] Invalid choice.")
# --- scan sítě --- #
def scan_network():
    ip_addr = input("[?] Enter IP address or range to scan (e.g., 192.168.1.1/24): ").strip()

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_addr)

    print(f"\n[+] Scanning {ip_addr}\n")

    result = srp(packet, timeout=3, verbose=0)[0]

    if not result:
        print("[red][-] No devices found. Exiting.")
        return

    devices.clear()

    for i, (s, r) in enumerate(result, start=1):
        devices.append({"ip": r.psrc, "mac": r.hwsrc})
        print(f"{i}. {r.psrc} | {r.hwsrc}")


# --- výběr cíle --- #
def select_target():
    if not devices:
        print("[red][-] No devices found. Please scan the network first.")
        return None, None

    while True:
        choice = input("\n[?] Enter the number of the target or 'r' for the router: ").strip()

        if choice.lower() == "r":
            router_ip = conf.route.route("0.0.0.0/0")[2]

            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip)
            ans = srp(packet, timeout=3, verbose=0)[0]

            if ans:
                router_mac = ans[0][1].hwsrc
                return router_ip, router_mac

            print("[red][-] Router not found.")
            continue

        try:
            idx = int(choice) - 1
            target = devices[idx]
            return target["ip"], target["mac"]
        except:
            print("[red][-] Invalid choice.")

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
        print("[yellow][!] Windows detected. Please run this script as Administrator to enable IP forwarding. (It probavly won't work on windows but Try it out)")
        value = "Enabled" if enable else "Disabled"

        subprocess.run(
            ["powershell", "-Command", f"Set-NetIPInterface -Forwarding {value}"],
            capture_output=True
        )


# --- cleanup --- #
def cleanup():
    toggle_forwarding(False)


atexit.register(cleanup)