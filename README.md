# TP1 — IDS/IPS maison (Python + Scapy)

Outil qui analyse une capture réseau (fichier PCAP ou interface en direct), compte les paquets
par protocole, détecte des attaques et produit un rapport JSON et un rapport PDF.

## Installation

```bash
poetry install
```

## Utilisation

```bash
# analyse d'un fichier PCAP (mode utilisé pour la correction)
poetry run tp1 --pcap capture.pcap --out report.json

# capture en direct pendant 30 s (nécessite les droits de capture : root ou setcap)
poetry run tp1 --iface eth0
```

Sorties :

- `report.json` : nombre de paquets par protocole, attaques détectées et flag ;
- `report.pdf` : résumé de l'analyse, tableau et graphique des volumes par protocole ;
- `app.log` : journal d'exécution.

## Détections

| Attaque | Méthode | Attaquant rapporté |
|---|---|---|
| ARP spoofing | une même IP annoncée par plusieurs MAC ; le coupable est la MAC qui envoie le plus de réponses ARP non sollicitées | adresse MAC |
| Scan de ports | une IP envoie des SYN (sans ACK) vers au moins 10 ports différents | adresse IP |
| Injection SQL | motifs suspects (`' OR 1=1`, `UNION SELECT`, `'--`…) dans l'URL ou le corps des requêtes HTTP, après décodage | adresse IP |

Le flag `ESGI{...}` est recherché uniquement dans les paquets des attaquants détectés, pour ne pas
retenir les faux flags présents ailleurs dans la capture. Le PDF propose aussi une règle `iptables`
de blocage pour chaque attaquant.

## Tests et qualité

```bash
poetry run pytest -v          # tests unitaires
poetry run ruff check src tests
pre-commit run --all-files    # hooks : ruff, ruff-format, autoflake...
```