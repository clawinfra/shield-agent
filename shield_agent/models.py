"""Data models for ShieldAgent scan results."""

from dataclasses import dataclass, field
from enum import Enum
import time


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Vulnerability:
    type: str
    description: str
    severity: RiskLevel
    line_number: int | None = None
    code_snippet: str | None = None


@dataclass
class ScanResult:
    contract_address: str
    contract_name: str
    scan_timestamp: float = field(default_factory=time.time)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    risk_level: RiskLevel = RiskLevel.LOW
    source_available: bool = False

    @staticmethod
    def compute_risk_level(score: int) -> RiskLevel:
        """Compute risk level from a numeric score."""
        if score >= 75:
            return RiskLevel.CRITICAL
        elif score >= 50:
            return RiskLevel.HIGH
        elif score >= 25:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
