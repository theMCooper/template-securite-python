from scapy.utils import rdpcap

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.lib import lire_arguments, ecrire_json
from tp1.utils.report import Report


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
