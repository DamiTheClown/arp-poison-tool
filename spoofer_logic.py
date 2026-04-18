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