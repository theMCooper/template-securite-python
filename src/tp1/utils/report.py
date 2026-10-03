from datetime import datetime
from fpdf import FPDF
import matplotlib.pyplot as plt
from tp1.utils.capture import Capture


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.stats = capture.sort_network_protocols()
        self.filename = filename
        self.title = f"RAPPORT-{datetime.now()}"
        self.summary = capture.get_summary()
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += f"<h1>{self.title}</h1>"
        content += self.summary
        content += self.array

        return content

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """
        pdf = FPDF()
        pdf.add_page()
        html = f"<h1>{self.title}</h1>"
        html += f"<p>{self.summary}</p>"
        html += self.array
        pdf.write_html(html)
        pdf.ln(6)
        if self.graph:
            pdf.image(self.graph, w=180)
        pdf.output(self.filename)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            protos = list(self.stats.keys())
            valeurs = list(self.stats.values())

            fig, ax = plt.subplots(figsize=(8, 5))
            ax.barh(protos, valeurs, color="#3498db")
            ax.set_title("Répartition des protocoles")
            ax.set_xlabel("Nombre de paquets")
            ax.invert_yaxis()
            fig.tight_layout()
            fig.savefig("graph.png", dpi=120)
            plt.close(fig)
            self.graph = "graph.png"

        elif param == "array":
                html = "<table border='1'><thead><tr><th>Protocole</th><th>Paquets</th></tr></thead><tbody>"
                for proto, nombre in self.stats.items():
                    html += f"<tr><td>{proto}</td><td>{nombre}</td></tr>"
                html += "</tbody></table>"
                self.array = html
