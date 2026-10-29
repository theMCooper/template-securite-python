import json
import re
from pathlib import Path
from fpdf import FPDF
from tp2.utils.config import logger


def texte_pdf(texte) -> str:
    """Rend un texte imprimable par la police Helvetica de fpdf2 (latin-1 seulement)."""
    texte = re.sub(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]", " ", str(texte))
    texte = texte.encode("latin-1", "replace").decode("latin-1")
    return re.sub(r"\S{61,}", lambda m: " ".join(re.findall(r".{1,60}", m.group())), texte)


def generate_report(rapport: dict, dossier: str | Path, infos: dict) -> Path:
    """Écrit <sha256>.json (toujours en premier) puis <sha256>.pdf. Renvoie le chemin du JSON."""
    dossier = Path(dossier)
    dossier.mkdir(parents=True, exist_ok=True)
    chemin_json = dossier / f"{rapport['sha256']}.json"
    with open(chemin_json, "w", encoding="utf-8") as fichier:
        json.dump(rapport, fichier, indent=2, ensure_ascii=False)

    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Rapport de triage", new_x="LMARGIN", new_y="NEXT")
        lignes = [
            ("fichier", infos.get("nom", "")),
            ("sha256", rapport["sha256"]),
            ("md5", rapport["md5"]),
            ("taille", rapport["size"]),
            ("type", rapport["file_type"]),
            ("entropie", rapport["entropy"]),
            ("famille", rapport["family_guess"]),
            ("score", f"{rapport['score']}/10 (avis : {infos.get('source', '')})"),
            ("MITRE ATT&CK", ", ".join(rapport["mitre_attack"])),
            ("résumé", rapport["llm_summary"]),
            ("flag", rapport["flag"]),
        ]
        lignes += [(cle, ", ".join(valeurs)) for cle, valeurs in rapport["iocs"].items() if valeurs]
        lignes += [("YARA", ", ".join(rapport["yara_matches"]))]
        lignes += [("injection ignorée", t) for t in infos.get("injections", [])]
        lignes += [("imports", ", ".join(rapport["imports"][:30]))]
        pdf.set_font("Helvetica", "", 9)
        for cle, valeur in lignes:
            pdf.multi_cell(0, 5, texte_pdf(f"{cle} : {valeur}"), align="L", new_x="LMARGIN", new_y="NEXT")
        pdf.output(str(dossier / f"{rapport['sha256']}.pdf"))
    except Exception:
        logger.exception(f"PDF impossible pour {rapport['sha256']}")  # le JSON noté existe déjà
    return chemin_json
