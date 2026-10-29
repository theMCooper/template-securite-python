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
# TP2 — Triage automatisé de malware

Outil qui analyse des fichiers suspects **sans jamais les exécuter** : empreintes, IOC, imports
(LIEF), règles YARA, avis d'un LLM (OpenRouter), puis un rapport JSON et un rapport PDF par fichier.

## Installation

```bash
poetry install
```

Clé OpenRouter (facultative) dans un fichier `.env` à la racine, non suivi par git :

```
OPENROUTER_API_KEY=sk-or-v1-...
```

Sans clé, ou sans réseau, l'outil fonctionne quand même avec un verdict de secours sans LLM.

## Utilisation

```bash
poetry run tp2 --samples ./samples --rules ./rules --out ./out
```

- `--samples` : dossier des fichiers à analyser ;
- `--rules` : dossier des règles YARA (celles fournies + `rules/triage_custom.yar`) ;
- `--out` : un `<sha256>.json` (format de l'énoncé) et un `<sha256>.pdf` par fichier.

Un fichier qui plante est noté dans `app.log` et l'analyse passe au suivant.

## Organisation

| Fichier | Rôle |
|---|---|
| `src/tp2/main.py` | arguments, boucle sur les fichiers, `analyser_fichier` |
| `src/tp2/utils/lib.py` | métadonnées, chaînes, IOC, flag, LIEF, YARA, comportement, score |
| `src/tp2/utils/llm.py` | `LLMClient`, `OpenRouterClient`, résumé envoyé, validation, verdict de secours |
| `src/tp2/utils/report.py` | écriture du JSON puis du PDF |
| `rules/triage_custom.yar` | 2 règles perso : injection de prompt, config C2 + clé Run |

## Choix d'analyse

- **Overlay seulement** : les échantillons sont un vrai ELF GNU suivi de données ajoutées.
  Si l'overlay contient du texte, on n'analyse que lui (les chaînes du programme GNU donneraient
  de faux IOC). Sinon, on lit tout le fichier.
- **Bruit** : une chaîne courte entourée de données aléatoires (bloc packé) est écartée.
- **Injection** : les phrases qui parlent à une IA ou demandent de déclarer le fichier sain sont
  retirées avant de chercher les IOC et le flag. Le faux flag et le faux domaine qu'elles
  contiennent disparaissent donc.
- **Flag** : on garde la chaîne `FLAG=ESGI{...}` seule sur sa ligne ; en cas de doute, `null`.
- **IOC** : les noms de fichiers (`urlmon.dll`, `gate.php`) ne sont pas des domaines ; les IP
  invalides, loopback ou multicast sont rejetées ; les IP privées sont gardées.
- **imports** : les vrais imports donnés par LIEF. Les noms d'API Windows trouvés dans le texte
  servent aux capacités, à la famille et aux codes MITRE.

## Sécurité de la partie LLM

1. On n'envoie qu'un résumé (hash, IOC, imports, YARA, quelques chaînes), entre balises
   `<untrusted_data>`. Les phrases d'injection et le flag ne sont jamais envoyés.
2. La réponse doit être un JSON avec `family_guess`, `mitre_attack`, `score` (entier de 0 à 10)
   et `summary`, sinon elle est rejetée.
3. Le score est calculé par le code ; le LLM ne peut le changer que de ±2, et jamais vers le bas
   si une injection a été détectée.

Modèle : `openrouter/free`. Le modèle de l'énoncé (`meta-llama/llama-3.3-70b-instruct:free`)
répond `404 : unavailable for free` depuis octobre 2026.

## Score

| Indice | Points |
|---|---|
| au moins une règle YARA (+1 par règle en plus, max +2) | +3 |
| C2 (domaine, IP ou URL) | +2 |
| clé Run | +1 |
| mutex | +1 |
| capacité suspecte (download, execute, network, shell, keylog, inject) | +1 |
| contenu packé (entropie ≥ 7,2) | +1 |
| tentative d'injection | +2 |

Plafonné à 10.

## Tests

```bash
poetry run pytest tests/tp2 -v
```
