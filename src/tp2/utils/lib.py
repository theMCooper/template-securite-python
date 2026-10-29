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
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\x00]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9](?![\w-])",re.IGNORECASE,)
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
MUTEX_RE = re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_.{}\-]{2,128}")
REGISTRY_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\x00-\x1f\"'<>|]+", re.IGNORECASE)
WIN_PATH_RE = re.compile(r"(?:\b[A-Za-z]:|%[A-Za-z_]+%)\\[^\x00-\x1f\"'<>|*?]+")
UNIX_PATH_RE = re.compile(r"(?<![\w/])/(?:tmp|etc|var|dev/shm|home|root|usr|bin)/[\w./-]+")
FLAG_LINE_RE = re.compile(r"\s*FLAG\s*[=:]\s*(ESGI\{[A-Za-z0-9_\-]{1,128}\})\s*")
FLAG_ANY_RE = re.compile(r"ESGI\{[A-Za-z0-9_\-]{1,128}\}")
FILE_EXTENSIONS = frozenset("dll exe sys so php html htm js txt log ini cfg dat bin tmp bat cmd ps1 vbs py c h o debug jpg png gif zip pdf doc pdb".split())
BENIGN_DOMAINS = ("gnu.org", "translationproject.org")
TRAILING_JUNK = ".,;:)]}'\" "
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

IOC_KEYS = ("domains", "ips", "urls", "mutex", "registry")

def extract_iocs(data: bytes) -> dict[str, list[str]]:
    """Extrait domaines, IP, URL, mutex et clés de registre des chaînes propres."""
    found: dict[str, set[str]] = {key: set() for key in IOC_KEYS}
    chaine, _ =split_strings(data);