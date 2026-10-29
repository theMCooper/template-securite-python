import argparse
import os
from pathlib import Path
from tp2.utils.lib import (
    analyser_comportement,
    calculer_score,
    charger_regles,
    extract_flag,
    extract_iocs,
    extraire_chaines,
    get_file_metadata,
    parse_binary,
    score_final,
    yara_scan,
)
from tp2.utils.config import logger
from tp2.utils.report import generate_report


def analyser_fichier(chemin: Path, regles, clients: list) -> tuple[dict, dict]:
    """Fait passer un fichier dans tout le pipeline. Renvoie (rapport JSON, infos pour le PDF)."""
    data = chemin.read_bytes()  # on lit les octets, on n'exécute jamais le fichier
    meta = get_file_metadata(data)
    iocs = extract_iocs(data)
    propres, injections = extraire_chaines(data)
    binaire = parse_binary(chemin)
    yara_matches = yara_scan(data, regles)
    comportement = analyser_comportement(data, iocs, binaire["imports"], meta["entropy"])

    score_code = calculer_score(iocs, yara_matches, comportement, injections)
    secours = {}
    resume = {}
    verdict, source = {}
    rapport = {  # clés dans l'ordre exact de l'énoncé
        **meta,
        "iocs": iocs,
        "imports": binaire["imports"],
        "yara_matches": yara_matches,
        "family_guess": verdict["family_guess"],
        "mitre_attack": sorted(set(comportement["mitre"]) | set(verdict["mitre_attack"])),
        "llm_summary": verdict["summary"],
        "score": score_final(score_code, verdict["score"], source, injections),
        "flag": extract_flag(data),
    }
    return rapport, {"nom": chemin.name, "source": source, "injections": injections}


def lire_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Lit les arguments de la ligne de commande du TP2.
    """
    parser = argparse.ArgumentParser(description="Triage automatisé de malware")
    parser.add_argument("--samples", type=Path, required=True,help="dossier des échantillons à analyser")
    parser.add_argument("--rules", type=Path, required=True,help="dossier des règles YARA")
    parser.add_argument("--out", type=Path, required=True,help="dossier de sortie (un JSON par échantillon)")
    return parser.parse_args(argv)

def main(argv: list[str] | None = None):
    """fonction main du programme"""
    logger.info("Starting TP2")
    args = lire_arguments(argv)
    if not args.samples.is_dir():
        logger.error("Dossier d'échantillons introuvable : %s", args.samples)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    return 0

if __name__ == "__main__":
    main()
