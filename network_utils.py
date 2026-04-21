from scapy.all import Ether, ARP, srp, conf
import platform
import subprocess
import atexit
import os

devices = []  # Seznam nalezených zařízení

# --- Sken sítě --- #
def scan_network():
    ip_addr = input("[?] Zadejte IP adresu včetně prefixu (např. 192.168.1.1/24): ")

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast
    arp = ARP(pdst=ip_addr)

    print(f"\n[*] Skenuji síť {ip_addr}...\n")
    result = srp(ether / arp, timeout=3, verbose=0)[0]

    if not result:
        print("[-] Žádná zařízení nenalezena.")
        return

    for counter, (sent, received) in enumerate(result, start=1):
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
        print(f"{counter}. | IP: {received.psrc} | MAC: {received.hwsrc}")


# --- Výběr oběti --- #
def select_target():
    if not devices:
        print("[-] Seznam zařízení je prázdný. Nejdřív spusťte scan_network().")
        return None, None

    router_ip = conf.route.route("0.0.0.0/0")[2]

    print(f"\n[+] Zjišťuji MAC adresu routeru ({router_ip})...")
    answered_list = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip),
        timeout=3, verbose=0
    )[0]

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
            print(f"[+] Vybrána oběť: IP: {target['ip']} | MAC: {target['mac']}")
            return target["ip"], target["mac"]
        except (ValueError, IndexError):
            print("[-] Neplatný výběr. Zkuste to znovu.")


# --- IP forwarding --- #
def toggle_forwarding(enable=True):
    system = platform.system()

    if system == "Linux":
        value = "1" if enable else "0"
        os.system(f"sudo sysctl -w net.ipv4.ip_forward={value}")

    elif system == "Windows":
        value = "Enabled" if enable else "Disabled"
        try:
            result = subprocess.run(
                ["powershell", "-Command", f"Set-NetIPInterface -Forwarding {value}"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                print(f"[-] CHYBA: Nepodařilo se nastavit IP forwarding.")
                print(f"    Detail: {result.stderr.strip()}")
                print(f"    Ujistěte se, že terminál běží JAKO SPRÁVCE.")
            else:
                print(f"[+] Windows IP Forwarding: {value}")
        except FileNotFoundError:
            print("[-] PowerShell nebyl nalezen.")

    else:
        print(f"[-] OS '{system}' není podporován.")


# --- Cleanup při ukončení --- #
def cleanup():
    print("\n[+] Vypínám IP forwarding...")
    toggle_forwarding(False)

atexit.register(cleanup) 