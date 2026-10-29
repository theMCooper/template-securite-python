import json

from tp2.utils.report import generate_report, texte_pdf

RAPPORT = {
    "sha256": "ab" * 32,
    "md5": "cd" * 16,
    "size": 10,
    "entropy": 4.2,
    "file_type": "ELF",
    "iocs": {"domains": ["c2.example.test"], "ips": [], "urls": [], "mutex": [], "registry": []},
    "imports": ["connect"],
    "yara_matches": ["R1"],
    "family_guess": "dropper",
    "mitre_attack": ["T1105"],
    "llm_summary": "Émojis 🚀 et chinois 恶意软件 : le PDF ne doit pas planter",
    "score": 8,
    "flag": None,
}


def test_texte_pdf():
    texte = texte_pdf("a\x00b 🚀 " + "x" * 130)
    assert "\x00" not in texte and "?" in texte
    assert max(len(mot) for mot in texte.split()) <= 60


def test_generate_report(tmp_path):
    chemin = generate_report(RAPPORT, tmp_path, {"nom": "x.bin", "injections": ["ignore previous"]})
    assert list(json.loads(chemin.read_text(encoding="utf-8"))) == list(RAPPORT)
    assert (tmp_path / f"{RAPPORT['sha256']}.pdf").read_bytes().startswith(b"%PDF")
    assert json.loads((tmp_path / "x.bin.triage.json").read_text(encoding="utf-8")) == RAPPORT
    assert (tmp_path / "x.triage.json").exists()


def test_generate_report_pdf_rate(tmp_path, monkeypatch):
    def panne(*args):
        raise RuntimeError("fpdf cassé")

    monkeypatch.setattr("tp2.utils.report.FPDF.output", panne)
    assert generate_report(RAPPORT, tmp_path, {}).exists()

