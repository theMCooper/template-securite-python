from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report
import sys

def parameter(args) -> list:
    pcap=""
    sortie=""
    for i in range(1,len(args)):
        if args[i] = "--pcap":
            pcap = args[i+1]
        if args[i] = "--out":
            sortie = args[i=1]
    return  [pcap,sortie]

def main():
    logger.info("Starting TP1")

    capture = Capture()
    capture.sort_network_protocols()
    capture.analyse("tcp")
    summary = capture.get_summary()

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()
