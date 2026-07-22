import re

from triage.models import Indicator, IndicatorType

# Un octeto válido: 0-255. Repetido cuatro veces con puntos.
_OCTETO = r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

PATTERNS = {
    IndicatorType.IPV4: re.compile(
        r"\b" + _OCTETO + r"(?:\." + _OCTETO + r"){3}\b"
        
    ),
    IndicatorType.SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
    IndicatorType.SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
    IndicatorType.MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
}


def extract(text: str) -> list[Indicator]:
    """Recorre el texto y devuelve todos los indicadores encontrados."""
    found = []
    for itype, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            found.append(
                Indicator(
                    type=itype,
                    value=match.group(0),
                    context=text.strip()[:120],
                )
            )
    return found