import hashlib
import ipaddress
import math
import re
from collections import Counter
import magic
from tp2.utils.config import logger

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
EXTENSIONS = set( "dll exe sys so php html htm js txt log ini cfg dat bin tmp bat cmd ps1 vbs py c h o jpg png gif zip pdf".split())
PONCTUATION = ".,;:)]}'\" "
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\x00]+", re.IGNORECASE)
DOMAINE_RE = re.compile(r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9](?![\w-])",re.IGNORECASE,)
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
MUTEX_RE = re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_.{}\-]{2,128}")
REGISTRE_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\x00-\x1f\"'<>|]+", re.IGNORECASE)
FLAG_SEUL_RE = re.compile(r"\s*FLAG\s*[=:]\s*(ESGI\{[A-Za-z0-9_-]{1,128}\})\s*")
FLAG_RE = re.compile(r"ESGI\{[A-Za-z0-9_-]{1,128}\}")
INJECTION_RE = re.compile(
    r"ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)"
    r"|ignore[rz]?\s+(?:les\s+)?(?:consignes|instructions)\s+pr[ée]c[ée]dentes"
    r"|\b(?:AI|LLM|assistant|model)[\s_-]*(?:instructions?|note|prompt)\b"
    r"|\bNOTE[\s_-]*TO[\s_-]*(?:AI|LLM)\b"
    r"|\bmark\s+(?:the|this)\s+(?:sample|file)\s+(?:as\s+)?(?:clean|safe|benign)"
    r"|\b(?:this|the)\s+(?:file|sample)\s+is\s+(?:clean|safe|benign)"
    r"|d[ée]clar\w*\s+(?:ce|le)\s+fichier\s+sain"
    r"|\bdisregard\b|\bhoneypot\b|report\s+only\s+this|<!--",
    re.IGNORECASE,
)
API_SUSPECTES = {
    "download": ["URLDownloadToFile", "InternetOpenUrl", "InternetReadFile"],
    "execute": ["WinExec", "CreateProcess", "ShellExecute", "system", "execve"],
    "network": ["WSASocket", "socket", "connect", "send", "recv"],
    "keylog": ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState"],
    "inject": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
}
MITRE = {
    "download": "T1105",
    "execute": "T1106",
    "keylog": "T1056.001",
    "inject": "T1055",
    "shell": "T1059.003",
    "persistance": "T1547.001",
    "web": "T1071.001",
    "packe": "T1027.002",
}


def shannon_entropy(donee: bytes) -> float:
    """Calcule l'entropie de Shannon en bits par octet (0 à 8)."""
    if not donee:
        return 0.0
    total = len(donee)
    return -sum((n / total) * math.log2(n / total) for n in Counter(donee).values())


def detect_file_type(donee: bytes) -> str:
    """Devine le type du fichier avec libmagic, sans jamais lever d'exception."""
    try:
        return magic.from_buffer(donee)
    except Exception:
        logger.warning("libmagic n'a pas pu identifier le fichier")
        return "unknown"


def get_file_metadata(donee: bytes) -> dict:
    """Rassemble les métadonnées notées du fichier"""
    return {
        "sha256": hashlib.sha256(donee).hexdigest(),
        "md5": hashlib.md5(donee).hexdigest(),
        "size": len(donee),
        "entropy": round(shannon_entropy(donee), 2),
        "file_type": detect_file_type(donee),
    }

def zone_utile(data: bytes) -> bytes:
    """Renvoie l'overlay (octets après la fin officielle du binaire) s'il contient du texte, sinon tout.
    """
    try:
        binaire = lief.parse(data)
    except Exception:
        binaire = None
    if binaire is not None:
        overlay = bytes(binaire.overlay)
        if re.search(rb"[\x20-\x7e]{6}|(?:[\x20-\x7e]\x00){6}", overlay):
            return overlay
    return data

def extraire_chaines(data: bytes) -> tuple[list[str], list[str]]:
    """Extrait les chaînes de la zone utile et les sépare en (propres, injections).
    Une chaîne courte entourée de données aléatoires des deux côtés est du hasard : on l'écarte.
    """
    zone = zone_utile(data)
    trouvees = []
    for motif, encodage in ((ASCII_RE, "ascii"), (UTF16_RE, "utf-16-le")):
        for m in motif.finditer(zone):
            debut, fin = m.start(), m.end()
            if fin - debut < 16:
                cotes = [zone[max(0, debut - 256) : debut], zone[fin : fin + 256]]
                cotes = [c for c in cotes if len(c) >= 128]
                if cotes and all(entropie(c) > 0.85 * math.log2(len(c)) for c in cotes):
                    continue
            trouvees.append((debut, m.group().decode(encodage)))
    trouvees.sort()
    propres = [t for _, t in trouvees if not INJECTION_RE.search(t)]
    injections = [t for _, t in trouvees if INJECTION_RE.search(t)]
    return propres, injections

def ip_valide(texte: str) -> bool:
    """Vrai si l'ip existe et est valide"""
    try:
        ip = ipaddress(texte)
    except ValueError:
        return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved or ip.is_link_local)

def extract_iocs(data: bytes) -> dict:
    """Extrait domaines, IP, URL, mutex et clés de registre des chaînes propres."""
    iocs = {"domains": set(), "ips": set(), "urls": set(), "mutex": set(), "registry": set()}
    propres, _ = extraire_chaines(data)
    for texte in propres:
        for url in URL_RE.findall(texte):
            url = url.rstrip(PONCTUATION)
            hote = (urlsplit(url).hostname or "").lower()
            if IP_RE.fullmatch(hote):
                if not ip_valide(hote):
                    continue
                iocs["ips"].add(hote)
            elif hote:
                iocs["domains"].add(hote)
            iocs["urls"].add(url)
        for domaine in DOMAINE_RE.findall(texte):
            if domaine.rsplit(".", 1)[-1].lower() not in EXTENSIONS:
                iocs["domains"].add(domaine.lower())
        iocs["ips"].update(ip for ip in IP_RE.findall(texte) if ip_valide(ip))
        iocs["mutex"].update(MUTEX_RE.findall(texte))
        iocs["registry"].update(cle.rstrip(PONCTUATION) for cle in REGISTRE_RE.findall(texte))
    return {cle: sorted(valeurs) for cle, valeurs in iocs.items()}

def extract_flag(data: bytes) -> str | None:
    """Renvoie le vrai flag, ou None en cas de doute."""
    propres, _ = extraire_chaines(data)
    candidats = {m.group(1) for t in propres if (m := FLAG_SEUL_RE.fullmatch(t))}
    if not candidats:
        candidats = {flag for t in propres for flag in FLAG_RE.findall(t)}
    if len(candidats) == 1:
        return candidats.pop()
    logger.warning(f"Flag absent ou ambigu ({len(candidats)} candidats)")
    return None

def parse_binary(path: str | Path) -> dict:
    """Renvoie format, imports, exports et sections d'un PE/ELF avec LIEF (listes vides sinon)."""
    resultat = {"format": "unknown", "imports": [], "exports": [], "sections": []}
    try:
        binaire = lief.parse(str(path))
    except Exception:
        binaire = None
    if binaire is None:
        return resultat
    resultat["format"] = str(binaire.format).split(".")[-1]  # "FORMATS.ELF" -> "ELF"
    resultat["imports"] = sorted({f.name for f in binaire.imported_functions if f.name})
    resultat["exports"] = sorted({f.name for f in binaire.exported_functions if f.name})
    resultat["sections"] = [
        {"name": s.name, "size": s.size, "entropy": round(s.entropy, 2)} for s in binaire.sections
    ]
    return resultat

def charger_regles(dossier: str | Path) -> yara.Rules | None:
    """Compile toutes les règles valides du dossier ; une règle cassée est ignorée."""
    valides = {}
    for i, fichier in enumerate(sorted(Path(dossier).glob("*.yar*"))):
        try:
            yara.compile(filepath=str(fichier))  # test du fichier seul
        except yara.Error as erreur:
            logger.warning(f"Règle ignorée {fichier.name} : {erreur}")
            continue
        valides[f"ns{i}"] = str(fichier)  # un espace de noms par fichier : pas de conflit de noms
    if not valides:
        logger.warning("Aucune règle YARA valide")
        return None
    return yara.compile(filepaths=valides)


def yara_scan(data: bytes, regles: yara.Rules | None) -> list[str]:
    """Renvoie les noms des règles YARA qui correspondent au fichier."""
    if regles is None:
        return []
    return sorted({m.rule for m in regles.match(data=data, timeout=60)})


def analyser_comportement(data: bytes, iocs: dict, imports: list[str], entropie_fichier: float) -> dict:
    """Déduit capacités, persistance, packing, codes MITRE et famille, sans LLM."""
    propres, _ = extraire_chaines(data)
    mots = set(imports) | {mot for t in propres for mot in re.findall(r"\w{3,}", t)}
    capacites = [
        cap for cap, apis in API_SUSPECTES.items() if any(m.startswith(api) for m in mots for api in apis)
    ]
    if any("cmd.exe" in t.lower() or "/bin/sh" in t for t in propres):
        capacites.append("shell")
    persistance = any(re.search(r"\\Run(?:Once)?\\", cle, re.IGNORECASE) for cle in iocs["registry"])
    packe = max(entropie_fichier, entropie(zone_utile(data))) >= 7.2

    mitre = {MITRE[c] for c in capacites if c in MITRE}
    if persistance:
        mitre.add(MITRE["persistance"])
    if iocs["urls"]:
        mitre.add(MITRE["web"])
    if packe:
        mitre.add(MITRE["packe"])

    if "keylog" in capacites:
        famille = "keylogger"
    elif "network" in capacites and ("shell" in capacites or "execute" in capacites):
        famille = "backdoor"
    elif "download" in capacites:
        famille = "dropper"
    elif packe:
        famille = "packed"
    elif iocs["domains"] or iocs["ips"] or iocs["urls"]:
        famille = "trojan"
    else:
        famille = "unknown"
    return {
        "capacites": sorted(capacites),
        "persistance": persistance,
        "packe": packe,
        "mitre": sorted(mitre),
        "famille": famille,
    }


def calculer_score(iocs: dict, yara_matches: list[str], comportement: dict, injections: list[str]) -> int:
    """Score de 0 à 10 calculé par le code, à partir de preuves fiables."""
    score = 0
    if yara_matches:
        score += 3 + min(2, len(yara_matches) - 1)
    if iocs["domains"] or iocs["ips"] or iocs["urls"]:
        score += 2

    if comportement["persistance"]:
        score += 1
    if iocs["mutex"]:
        score += 1
    if comportement["capacites"]:
        score += 1
    if comportement["packe"]:
        score += 1
    if injections:
        score += 2
    return min(score, 10)


def score_final(score_code: int, score_llm: int, source: str, injections: list[str]) -> int:
    """Le code décide : le LLM ne bouge le score que de ±2, et jamais vers le bas si injection."""
    if source == "fallback":
        return score_code
    final = score_code + max(-2, min(2, score_llm - score_code))
    if injections:
        final = max(final, score_code)
    return max(0, min(10, final))

