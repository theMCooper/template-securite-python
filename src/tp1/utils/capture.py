import re
from collections import Counter
from urllib.parse import unquote_plus

from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import ARP
from scapy.plist import PacketList
from src.tp1.utils.lib import choose_interface, protocole
from tp1.utils.config import logger
from scapy.all import sniff

class Capture:
    def __init__(self,pkts: PacketList | None = None,interface: str = "") -> None:
        if pkts is not None:
            self.interface = ""
            self.pkts = pkts
        else:
            if interface == "":
                interface = choose_interface()
            self.interface = interface
            self.pkts = self.capture_traffic()
        self.attacks = []
        self.flag = ""
        self.summary = ""

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
            for nom in protocole(pkt):  # un paquet compte pour chacune de ses couches
                if nom not in protocols:
                    protocols[nom] = 0
                protocols[nom] += 1
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
            if pkt.haslayer(IP):
                src = pkt[IP].src
            else :
                continue
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

    def detect_sql_injection(self) -> list[str]:
        """
        Détecte les injections SQL dans les requêtes HTTP.
        Renvoie la liste des IP qui ont envoyé une requête suspecte.
        """
        attaquants = []
        mots_sqli = [
            "or 1=1",
            "' or '1'='1",
            "union select",
            "union all select",
            "/**/",
            "'--",
            "'#",
            "drop table",
            "information_schema",
            "sleep(",
        ]
        for pkt in self.pkts:
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                continue

            texte = bytes(pkt[TCP].payload).decode(errors="ignore")
            if not texte.startswith(("GET ", "POST ")):
                continue

            premiere_ligne = texte.split("\r\n")[0]
            corps = texte.split("\r\n\r\n")[-1]
            texte = unquote_plus(premiere_ligne + " " + corps).lower()
            for mot in mots_sqli:
                if mot in texte and pkt[IP].src not in attaquants:
                    logger.warning(f"[SQLI] {pkt[IP].src} : {premiere_ligne}")
                    attaquants.append(pkt[IP].src)

        return sorted(attaquants)

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

    def get_attacks(self) -> list[dict]:
        """
        Renvoie toutes les attaques au format de report.json
        """
        attaques = []
        for mac in self.detect_arp_spoofing():
            attaques.append({"type": "arp_spoofing", "attacker": mac})
        for ip in self.scan_port_syn():
            attaques.append({"type": "port_scan", "attacker": ip})
        for ip in self.detect_sql_injection():
            attaques.append({"type": "sql_injection", "attacker": ip})
        return attaques

    def trouver_flag(self, ips_attaquants: list[str]) -> str:
        """
        Cherche ESGI{...} dans les requêtes HTTP envoyées par les attaquants
        """
        for pkt in self.pkts:
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                continue
            if pkt[IP].src not in ips_attaquants:
                continue
            texte = bytes(pkt[TCP].payload).decode(errors="ignore")
            if not texte.startswith(("GET ", "POST ")):
                continue
            resultat = re.search(r"ESGI\{[^}]+\}", texte)
            if resultat:
                return resultat.group()
        return ""

    def analyse(self) -> None:
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

        self.attacks = self.get_attacks()
        if len(self.attacks) == 0:
            logger.info("Aucune attaque détectée, tout va bien")

        ips_attaquants = []
        for attaque in self.attacks:
            if attaque["type"] != "arp_spoofing":
                ips_attaquants.append(attaque["attacker"])
        self.flag = self.trouver_flag(ips_attaquants)
        logger.info(f"Flag : {self.flag}")
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
        summary = f"{len(self.pkts)} paquets analysés.<br>"
        if len(self.attacks) == 0:
            summary += "Aucune attaque détectée, tout va bien.<br>"
        else:
            summary += f"{len(self.attacks)} attaque(s) détectée(s) :<br>"
            for attaque in self.attacks:
                summary += f"- {attaque['type']} : attaquant {attaque['attacker']}<br>"
        if self.flag != "":
            summary += f"Flag : {self.flag}<br>"
        return summary
