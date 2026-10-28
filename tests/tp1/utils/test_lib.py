from scapy.layers.http import HTTP, HTTPResponse
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.tls.record import TLS

from src.tp1.utils.lib import hello_world, choose_interface, protocole


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


def test_protocole():
    assert protocole(Ether() / ARP()) == ["Ethernet", "ARP"]
    assert protocole(IP() / ICMP()) == ["IP", "ICMP"]
    assert protocole(IP() / TCP() / HTTP() / HTTPResponse()) == ["IP", "TCP", "HTTP"]
    assert protocole(IP() / TCP() / TLS()) == ["IP", "TCP", "TLS"]
    assert protocole(Ether() / IPv6() / UDP()) == ["Ethernet", "IPV6", "UDP"]

def test_select():
    with patch("builtins.input", return_value="2"):  # simule l'utilisateur qui tape 2
        resultat = select(["lo", "eth0"], "choix : ")

    assert resultat == "eth0"


def test_choose_interface():
    with (
        patch("tp1.utils.lib.get_if_list", return_value=["lo", "wlp3s0"]),
        patch("builtins.input", return_value="2"),
    ):
        assert choose_interface() == "wlp3s0"