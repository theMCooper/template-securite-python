from scapy.all import get_if_list
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, TCP, UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.tls.record import TLS

from tp1.utils.config import logger

def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"

def select(options,invite)-> str:
    """selectione une interface à écouter"""
    for i in range(len(options)):
        logger.info(f'{i+1}.{options[i]}')
    while True:
        saisie = input(invite)
        if saisie.isdigit() and 1 <= int(saisie) <= len(options):
            return options[int(saisie) - 1]
        logger.warning("Choix invalide, réessaie.")


def protocole(pkt) -> list[str]:
    """
    Renvoie TOUS les protocoles présents dans le paquet
    """
    noms = []
    if pkt.haslayer(Ether):
        noms.append("Ethernet")
    if pkt.haslayer(ARP):
        noms.append("ARP")
    if pkt.haslayer(IP):
        noms.append("IP")
    if pkt.haslayer(IPv6):
        noms.append("IPV6")
    if pkt.haslayer(TCP):
        noms.append("TCP")
    if pkt.haslayer(UDP):
        noms.append("UDP")
    if pkt.haslayer(ICMP):
        noms.append("ICMP")
    if pkt.haslayer(DNS):
        noms.append("DNS")
    if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
        noms.append("HTTP")
    if pkt.haslayer(TLS):
        noms.append("TLS")
    return noms


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    return select(get_if_list(),"choisie une interfaces: ")
