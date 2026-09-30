from scapy.all import get_if_list
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.l2 import ARP


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"

def select(options,invite) -> str:
    for i in range(len(options)):
        print(f'{i+1}.{options[i]}')
    while True:
        saisie = input(invite)
        if saisie.isdigit() and 1 <= int(saisie) <= len(options):
            return options[int(saisie) - 1]
        print("Choix invalide, réessaie.")


def protocole(pkt):
    if DNS in pkt:   return "DNS"
    if ARP in pkt:   return "ARP"
    if ICMP in pkt:  return "ICMP"
    if TCP in pkt:   return "TCP"
    if UDP in pkt:   return "UDP"
    return pkt.lastlayer().name

def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    return select(get_if_list(),"choisie une interfaces: ")
