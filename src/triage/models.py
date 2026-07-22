

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"

class Verdict(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass(frozen=True)
class Indicator:
    type: IndicatorType
    value: str
    source: str = ""
    context: str = ""
    seen_at: datetime | None = None


@dataclass
class Enrichment:
    provider: str
    available: bool = True
    raw: dict = field(default_factory=dict)
    error: str | None = None
    detection_ratio: float | None = None
    abuse_confidence: int | None = None
    domain_age_days: int | None = None
    pulse_count: int | None = None


@dataclass
class ScoredIndicator:
    indicator: Indicator
    enrichments: list = field(default_factory=list)
    score: int = 0
    verdict: Verdict = Verdict.UNKNOWN
    reasons: list = field(default_factory=list)
    attack_techniques: list = field(default_factory=list)
    recommendation: str = ""