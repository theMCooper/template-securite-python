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

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
