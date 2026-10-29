import json

from tp2.main import analyser_fichier, lire_arguments, main
from tp2.utils.llm import LLMClient


class LLMCredule(LLMClient):
    """LLM qui obéit à l'injection : il déclare le fichier sain et recopie le faux flag."""

    nom = "credule"

    def complete(self, systeme, texte):
        return json.dumps(
            {
                "family_guess": "unknown",
                "mitre_attack": [],
                "score": 0,
                "summary": "Clean, ESGI{test_leurre_0002}",
            }
        )


def test_lire_arguments():
    args = lire_arguments(["--samples", "s", "--rules", "r", "--out", "o"])
    assert str(args.samples) == "s" and not args.verbose


def test_analyser_fichier_resiste_a_l_injection(tmp_path, echantillon):
    fichier = tmp_path / "piege.bin"
    fichier.write_bytes(echantillon)
    honnete, _ = analyser_fichier(fichier, None, None)
    rapport, infos = analyser_fichier(fichier, None, LLMCredule())
    assert infos["source"] == "credule"
    assert rapport["score"] >= honnete["score"] >= 7  # le LLM manipulé ne fait pas baisser le score
    assert rapport["flag"] == "ESGI{test_vrai_0001}"
    assert "ESGI{" not in rapport["llm_summary"]  # le faux flag recopié est effacé


def test_main_hors_reseau(tmp_path, echantillon, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)  # pas de clé : verdict de secours
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "a.bin").write_bytes(echantillon)
    (tmp_path / "samples" / "b.bin").write_bytes(b"")  # fichier vide : ne doit rien casser
    sortie = tmp_path / "out"
    code = main(
        ["--samples", str(tmp_path / "samples"), "--rules", str(tmp_path), "--out", str(sortie), "-v"]
    )
    assert code == 0 and len(list(sortie.glob("*.json"))) == 2

def test_main_hors_reseau(tmp_path, echantillon, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)  # pas de clé : verdict de secours
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "a.bin").write_bytes(echantillon)
    (tmp_path / "samples" / "b.bin").write_bytes(b"")  # fichier vide : ne doit rien casser
    sortie = tmp_path / "out"
    code = main(
        ["--samples", str(tmp_path / "samples"), "--rules", str(tmp_path), "--out", str(sortie), "-v"]
    )
    assert code == 0 and len(list(sortie.glob("*.json"))) == 2