import argparse
import json

from scapy.utils import rdpcap

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report

def lire_arguments(argv: list[str] | None = None):
    """parser d'argument"""
    parser = argparse.ArgumentParser(description="IDS maison : analyse une capture réseau")
    parser.add_argument("--pcap", help="fichier PCAP à analyser")
    parser.add_argument("--iface", default="", help="interface pour une capture en direct")
    parser.add_argument("--out", default="report.json", help="fichier JSON de sortie")
    return parser.parse_args(argv)


def ecrire_json(chemin: str, capture: Capture):
    """
    Écrit le rapport JSON demandé par le TP
    """
    rapport = {
        "protocols": capture.sort_network_protocols(),
        "attacks": capture.attacks,
        "flag": capture.flag,
    }
    with open(chemin, "w") as fichier:
        json.dump(rapport, fichier, indent=2)
    logger.info(f"Rapport JSON écrit dans {chemin}")

def main(argv: list[str] | None = None):
    """fonction main du programme"""
    logger.info("Starting TP1")
    args = lire_arguments(argv)

    if args.pcap:
        logger.info(f"Lecture du fichier {args.pcap}")
        capture = Capture(rdpcap(args.pcap))
    else:
        capture = Capture(interface=args.iface)

    capture.analyse()
    ecrire_json(args.out, capture)

    filename = "report.pdf"
    report = Report(capture, filename, capture.get_summary())
    report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()
