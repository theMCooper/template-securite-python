from collections import Counter

from _pytest import capture
from scapy.plist import PacketList
from src.tp1.utils.lib import choose_interface, protocole
from tp1.utils.config import logger
from scapy.all import sniff

class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.pkts = self.capture_traffic()
        self.summary =  self._gen_summary()

    def capture_traffic(self) -> PacketList:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")
        return sniff(iface=interface,timeout=30)

    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols
        """
        protocols = self.get_all_protocols()
        protocols_sorted = dict(Counter(protocols).most_common())
        return protocols_sorted

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        protocols = {}
        for pkt in self.pkts:
            nom = protocole(pkt)
            if nom not in protocols:
                protocols[nom]=0
            protocols[nom]+=1
        return protocols

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.info(f"All protocols: {all_protocols}")
        logger.info(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def detect_arp_spoofing(self) -> dict:
        """
            detecte les tentatives arp spoofing
        """
        arp_table={}
        spoofing_table={}
        for pkt in self.pkts:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                ip,mac = pkt[ARP].psrc , pkt[ARP].hwrc
                if ip not in arp_table:
                    arp_table[ip] = mac
                elif arp_table[ip] != mac:
                    logger.info(f"[!] ALERTE : {ip} était {arp_table[ip]}, maintenant {mac}")
                    arp_table[ip] = mac
                    spoofing_table[ip] = mac
        return spoofing_table;

    def scan_port_SYN(self) -> list:
        """
            detecte les scan syn
        """
        syn_scan = {}
        scan_probable =[]
        for pkt in self.pkts:
            if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
                src = pkt[ip].src
                if src not in syn_scan:
                    syn_scan[src] = []
                syn_scan[src].append(pkt[TCP].dport)
                if len(syn_scan[src]) > 10:
                     print(f"[!] {src} a touché {len(seen[src])} ports -> scan  probable")
                     scan_probable.append(src)
        return scan_probable


                
    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
