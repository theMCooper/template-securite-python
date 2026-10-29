import hashlib
import math
from collections import Counter
import magic
from tp2.utils.config import logger

"""partie 1 avoir les metadonnée du fichier"""
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