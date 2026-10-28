import pytest
from scapy.layers.inet import IP, TCP

from tp1.utils.capture import Capture
from tp1.utils.report import Report


@pytest.fixture
def capture():
    """Une capture de 2 paquets TCP"""
    return Capture([IP() / TCP(), IP() / TCP()])


def test_init(capture):
    report = Report(capture, "test.pdf", "")

    assert report.filename == "test.pdf"
    assert report.stats == {"IP": 2, "TCP": 2}


def test_concat_report(capture):
    report = Report(capture, "test.pdf", "")
    report.title = "Titre"
    report.array = "Tableau"

    assert report.concat_report() == "<h1>Titre</h1>Tableau"


def test_generate(capture, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # graph.png est créé dans un dossier temporaire
    report = Report(capture, "test.pdf", "")

    report.generate("graph")
    report.generate("array")

    assert report.graph == "graph.png"
    assert "<td>TCP</td><td>2</td>" in report.array


def test_save(capture, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report = Report(capture, "test.pdf", "")

    report.save("test.pdf")

    assert (tmp_path / "test.pdf").exists()
