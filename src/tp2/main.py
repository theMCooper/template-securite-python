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
from tp2.utils.llm import verdict_secours, construire_resume, llm_triage, OpenRouterClient
from tp2.utils.report import generate_report


def lire_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Lit les arguments de la ligne de commande du TP2.
    """
    parser = argparse.ArgumentParser(description="Triage automatisé de malware")
    parser.add_argument("--samples", type=Path, required=True,help="dossier des échantillons à analyser")
    parser.add_argument("--rules", type=Path, required=True,help="dossier des règles YARA")
    parser.add_argument("--out", type=Path, required=True,help="dossier de sortie (un JSON par échantillon)")
    return parser.parse_args(argv)

def analyser_fichier(chemin: Path, regles, client) -> tuple[dict, dict]:
    """Fait passer un fichier dans tout le pipeline. Renvoie (rapport JSON, infos pour le PDF)."""
    data = chemin.read_bytes()
    meta = get_file_metadata(data)
    iocs = extract_iocs(data)
    propres, injections = extraire_chaines(data)
    binaire = parse_binary(chemin)
    yara_matches = yara_scan(data, regles)
    comportement = analyser_comportement(data, iocs, binaire["imports"], meta["entropy"])

    score_code = calculer_score(iocs, yara_matches, comportement, injections)
    secours = verdict_secours(comportement, iocs, yara_matches, injections, score_code)
    resume = construire_resume(
        meta, iocs, binaire["imports"], yara_matches, comportement, injections, propres
    )
    verdict, source = llm_triage(resume, client, secours)

    rapport = {
        **meta,
        "iocs": iocs,
        "imports": binaire["imports"],
        "yara_matches": yara_matches,
        "family_guess": verdict["family_guess"],
        "mitre_attack": sorted(set(comportement["mitre"]) | set(verdict["mitre_attack"])),
        "llm_summary": verdict["summary"],
        "score": score_final(score_code, verdict["score"], source, injections),
        "flag": extract_flag(data),  # le flag vient du code, jamais du LLM
    }
    return rapport, {"nom": chemin.name, "source": source, "injections": injections}


def main(argv: list[str] | None = None) -> int:
    """fonction main du programme"""
    logger.info("Starting TP2")
    args = lire_arguments(argv)
    args.out.mkdir(parents=True, exist_ok=True)

    regles = charger_regles(args.rules)
    cle = os.getenv("OPENROUTER_API_KEY")
    client = OpenRouterClient(cle) if cle else None
    for chemin in sorted(args.samples.iterdir()):
        if not chemin.is_file():
            continue
        try:
            rapport, infos = analyser_fichier(chemin, regles, client)
            generate_report(rapport, args.out, infos)
            logger.info(f"{chemin.name} : score {rapport['score']}, famille {rapport['family_guess']}")
        except Exception:
            logger.exception(f"Analyse impossible pour {chemin.name}")  # on passe au fichier suivant
    return 0


if __name__ == "__main__":
    main()