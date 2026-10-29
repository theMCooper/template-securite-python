import hashlib
import math
import re
from collections import Counter
import magic
from tp2.utils.config import logger

"""partie 1 avoir les métadonnée du fichier"""
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

"""partie 2 extract loc extract_iocs(data)"""
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
