from collections import Counter

from _pytest import capture
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import ARP
from scapy.plist import PacketList
from src.tp1.utils.lib import choose_interface, protocole
from tp1.utils.config import logger
from scapy.all import sniff

class Capture:
    def __init__(self,pkts: list | None = None) -> None:
        if pkts is None:
            self.interface = choose_interface()
            self.pkts = self.capture_traffic()
        else:
            self.interface = ""
            self.pkts = pkts
        self.attacks = []
        self.summary = self._gen_summary()

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

    def scan_port_syn(self, seuil: int = 10) -> list[str]:
        """
        Détecte les scans de ports. Renvoie la liste des IP qui scannent.
        """
        ports_par_ip = {}
        for pkt in self.pkts:
            if not pkt.haslayer(TCP):
                continue
            if pkt[TCP].flags != "S":
                continue
            src = pkt[IP].src
            port = pkt[TCP].dport
            if src not in ports_par_ip:
                ports_par_ip[src] = []
            if port not in ports_par_ip[src]:
                ports_par_ip[src].append(port)
        scans = []
        for src, ports in ports_par_ip.items():
            nb_ports = len(ports)
            if nb_ports >= seuil:
                logger.warning(f"[SCAN] {src} a envoyé des SYN vers {nb_ports} ports différents")
                scans.append(src)
        return sorted(scans)

    def detect_arp_spoofing(self) -> list[str]:
        """
        Détecte l'ARP spoofing et renvoie la liste des MAC des attaquants.

        """
        requetes = set()
        non_sollicitees = {}

        for pkt in self.pkts:
            if not pkt.haslayer(ARP):
                continue
            a = pkt[ARP]
            if a.op == 1:
                requetes.add((a.psrc, a.pdst))
            elif a.op == 2 and a.pdst != a.psrc and (a.pdst, a.psrc) not in requetes:
                non_sollicitees[a.hwsrc] = non_sollicitees.get(a.hwsrc, 0) + 1

        attaquants = []
        for mac, n in non_sollicitees.items():
            if n >= 3:
                attaquants.append(mac)
        return sorted(attaquants)

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
        arp_spoofing = self.detect_arp_spoofing()
        syn_scan = self.scan_port_SYN()
        if arp_spoofing :
            logger.info("detecte une tentative attaque arp")
        if syn_scan:
            logger.info("detecte une tentative de synscan")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

                
    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
