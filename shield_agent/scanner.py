"""Core vulnerability scanner for smart contracts."""

from __future__ import annotations

import re
import time

import requests

from .models import RiskLevel, ScanResult, Vulnerability


# Vulnerability pattern definitions: (regex_pattern, description, severity)
VULN_PATTERNS: dict[str, list[tuple[str, str, RiskLevel]]] = {
    "reentrancy": [
        (
            r"\.call\{value:.*\}.*\(\s*\"\"\s*\)[\s\S]{0,200}(?:balances|balance)\[",
            "External call with value before state update — potential reentrancy",
            RiskLevel.CRITICAL,
        ),
        (
            r"\.call\{value:",
            "Low-level call with value transfer detected",
            RiskLevel.MEDIUM,
        ),
    ],
    "flash_loan": [
        (
            r"flashLoan|flashloan|flash_loan",
            "Flash loan function detected — verify callback validation",
            RiskLevel.MEDIUM,
        ),
    ],
    "price_oracle_manipulation": [
        (
            r"getReserves\(\)|slot0\(\)",
            "Spot price oracle usage — vulnerable to manipulation in single block",
            RiskLevel.HIGH,
        ),
        (
            r"latestAnswer\(\)|latestRoundData\(\)",
            "Chainlink oracle usage — check for stale price handling",
            RiskLevel.LOW,
        ),
    ],
    "access_control": [
        (
            r"tx\.origin",
            "Use of tx.origin for authorization — vulnerable to phishing attacks",
            RiskLevel.CRITICAL,
        ),
        (
            r"selfdestruct|SELFDESTRUCT",
            "selfdestruct present — verify access controls",
            RiskLevel.HIGH,
        ),
        (
            r"delegatecall",
            "delegatecall usage — verify target is trusted",
            RiskLevel.HIGH,
        ),
    ],
    "integer_overflow": [
        (
            r"pragma solidity\s+(?:0\.[0-6]\.\d+|\^0\.[0-6]\.\d+)",
            "Solidity version <0.8.0 without built-in overflow checks",
            RiskLevel.MEDIUM,
        ),
        (
            r"unchecked\s*\{",
            "Unchecked arithmetic block — verify no overflow possible",
            RiskLevel.MEDIUM,
        ),
    ],
}

# Severity weights for risk scoring
SEVERITY_WEIGHTS = {
    RiskLevel.LOW: 5,
    RiskLevel.MEDIUM: 15,
    RiskLevel.HIGH: 30,
    RiskLevel.CRITICAL: 50,
}


class ContractScanner:
    """
    Scans smart contracts for vulnerabilities using static analysis
    and pattern matching against known exploit signatures.
    """

    ETHERSCAN_API = "https://api.etherscan.io/api"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or ""

    def fetch_source(self, address: str) -> dict:
        """Fetch contract source code from Etherscan.

        Returns dict with keys: name, source, compiler, abi (all str).
        """
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        }
        if self.api_key:
            params["apikey"] = self.api_key

        try:
            resp = requests.get(self.ETHERSCAN_API, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            if data.get("status") != "1" or not data.get("result"):
                return {"name": "", "source": "", "compiler": "", "abi": ""}

            result = data["result"][0]
            return {
                "name": result.get("ContractName", ""),
                "source": result.get("SourceCode", ""),
                "compiler": result.get("CompilerVersion", ""),
                "abi": result.get("ABI", ""),
            }
        except Exception:
            return {"name": "", "source": "", "compiler": "", "abi": ""}

    def analyse_source(self, source: str) -> list[Vulnerability]:
        """Run pattern-matching analysis on Solidity source code."""
        vulns: list[Vulnerability] = []

        for vuln_type, patterns in VULN_PATTERNS.items():
            for pattern, description, severity in patterns:
                matches = list(re.finditer(pattern, source))
                if matches:
                    # Find approximate line number of first match
                    first = matches[0]
                    line_no = source[: first.start()].count("\n") + 1
                    snippet_start = max(0, first.start() - 40)
                    snippet_end = min(len(source), first.end() + 40)
                    snippet = source[snippet_start:snippet_end].strip()

                    vulns.append(
                        Vulnerability(
                            type=vuln_type,
                            description=f"{description} ({len(matches)} occurrence(s))",
                            severity=severity,
                            line_number=line_no,
                            code_snippet=snippet[:200],
                        )
                    )
        return vulns

    def compute_risk_score(self, vulns: list[Vulnerability]) -> int:
        """Compute aggregate risk score (0-100) from vulnerabilities."""
        if not vulns:
            return 0
        total = sum(SEVERITY_WEIGHTS.get(v.severity, 0) for v in vulns)
        return min(100, total)

    def scan(self, address: str, network: str = "mainnet", dry_run: bool = False) -> ScanResult:
        """Fetch contract source, run analysis, return structured result.

        Args:
            address: Contract address (0x...).
            network: Network name (currently only mainnet supported).
            dry_run: If True, skip fetching source and return empty result.
        """
        if dry_run:
            return ScanResult(
                contract_address=address,
                contract_name="(dry-run)",
                source_available=False,
            )

        source_data = self.fetch_source(address)
        source = source_data["source"]
        name = source_data["name"] or address[:10]

        if not source:
            return ScanResult(
                contract_address=address,
                contract_name=name,
                scan_timestamp=time.time(),
                source_available=False,
            )

        vulns = self.analyse_source(source)
        score = self.compute_risk_score(vulns)
        level = ScanResult.compute_risk_level(score)

        return ScanResult(
            contract_address=address,
            contract_name=name,
            scan_timestamp=time.time(),
            vulnerabilities=vulns,
            risk_score=score,
            risk_level=level,
            source_available=True,
        )
