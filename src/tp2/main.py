import argparse
import os
from pathlib import Path

from tp2.utils.config import logger

def lire_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Lit les arguments de la ligne de commande du TP2.
    """
    parser = argparse.ArgumentParser(description="Triage automatisé de malware")
    parser.add_argument("--samples", type=Path, required=True,help="dossier des échantillons à analyser")
    parser.add_argument("--rules", type=Path, required=True,help="dossier des règles YARA")
    parser.add_argument("--out", type=Path, required=True,help="dossier de sortie (un JSON par échantillon)")
    parser.add_argument("-v", "--verbose", action="store_true",help="logs détaillés (niveau DEBUG)")
    return parser.parse_args(argv)

def main(argv: list[str] | None = None):
    """fonction main du programme"""
    logger.info("Starting TP2")
    args = lire_arguments(argv)

if __name__ == "__main__":
    main()
