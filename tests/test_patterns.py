import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from triage.extractors.patterns import extract
from triage.models import IndicatorType


def _values(text, itype):
    """Devuelve solo los valores extraídos de un tipo dado."""
    return {i.value for i in extract(text) if i.type == itype}


def test_extrae_ips_validas():
    text = "Conexion desde 192.168.1.1 hacia 8.8.8.8"
    assert _values(text, IndicatorType.IPV4) == {"192.168.1.1", "8.8.8.8"}


def test_rechaza_ip_imposible():
    text = "IP falsa 999.999.999.999 en el log"
    assert _values(text, IndicatorType.IPV4) == set()


def test_texto_sin_ips():
    text = "Esta linea no tiene ninguna direccion"
    assert _values(text, IndicatorType.IPV4) == set()


def test_extrae_los_tres_hashes():
    text = ("md5 d41d8cd98f00b204e9800998ecf8427e "
            "sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 "
            "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert _values(text, IndicatorType.MD5) == {"d41d8cd98f00b204e9800998ecf8427e"}
    assert _values(text, IndicatorType.SHA1) == {"da39a3ee5e6b4b0d3255bfef95601890afd80709"}
    assert _values(text, IndicatorType.SHA256) == {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}


def test_sha256_no_se_fragmenta_en_md5():
    # El SHA256 no debe producir ningun MD5 ni SHA1 falso.
    text = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert _values(text, IndicatorType.MD5) == set()
    assert _values(text, IndicatorType.SHA1) == set()
    assert _values(text, IndicatorType.SHA256) == {text}