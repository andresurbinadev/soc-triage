import re

from triage.models import Indicator, IndicatorType


# Extensiones que tienen forma de dominio pero son nombres de archivo.
# Decision de diseño: preferimos una denylist corta a mantener la lista
# completa de TLDs validos (>1500 y cambiante).
_EXT_ARCHIVO = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "msi",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    "zip", "rar", "7z", "gz", "tar", "iso", "img",
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico",
    "log", "tmp", "dat", "bin", "cfg", "ini", "xml", "json", "html", "htm",
    "py", "java", "class", "so", "dmg", "app",
}

# Un octeto válido: 0-255. Repetido cuatro veces con puntos.
_OCTETO = r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"



PATTERNS = {
    IndicatorType.DOMAIN: re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
    ),
    IndicatorType.IPV4: re.compile(
        r"\b" + _OCTETO + r"(?:\." + _OCTETO + r"){3}\b"
        
    ),
    IndicatorType.SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
    IndicatorType.SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
    IndicatorType.MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
}


def _es_nombre_archivo(value: str) -> bool:
    """True si lo que sigue al ultimo punto es una extension conocida."""
    return value.rsplit(".", 1)[-1].lower() in _EXT_ARCHIVO

def extract(text: str) -> list[Indicator]:
    """Recorre el texto y devuelve todos los indicadores encontrados."""
    found = []
    for itype, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            if itype is IndicatorType.DOMAIN and _es_nombre_archivo(value):
                continue
            found.append(
                Indicator(
                    type=itype,
                    value=value,
                    context=text.strip()[:120],
                )
            )
    return found