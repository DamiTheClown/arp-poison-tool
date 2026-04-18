# main.py - TODO LIST

# 1. TODO: Importovat funkce z network_utils a spoofer_logic

# 2. TODO: Získat od uživatele vstupní data (IP oběti a IP routeru)
# 3. TODO: Zavolat skener a zjistit MAC adresy oběti i routeru

# 4. TODO: Hlavní smyčka útoku (try - except)
#    - V 'try' bloku: volat spoof() v nekonečném cyklu (while True)
#    - Přidat malou pauzu (time.sleep(2)), ať nezahltíte síť
#    - V 'except KeyboardInterrupt' (po zmáčknutí Ctrl+C):
#        - Zavolat restore() pro opravu sítě
#        - Vypnout IP forwarding
#        - Uložit .pcap soubor