"""Substrate/Rust pallet vulnerability scanner for ClawChain.

Performs static analysis on Substrate pallet source trees, detecting common
vulnerability patterns in Rust/FRAME pallet code. Operates at three levels:

- ``analyse_file``   — single ``.rs`` file
- ``analyse_pallet`` — directory of ``.rs`` files (one pallet)
- ``scan_chain``     — directory of pallets (full chain audit)
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from .models import (
    ChainAuditReport,
    PalletScanResult,
    RiskLevel,
    Vulnerability,
)

# ---------------------------------------------------------------------------
# Severity weights — identical to EVM scanner for consistent scoring
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 50,
    RiskLevel.HIGH: 30,
    RiskLevel.MEDIUM: 15,
    RiskLevel.LOW: 5,
}

# ---------------------------------------------------------------------------
# Vulnerability pattern definitions
# Each entry: (regex_pattern, description, severity)
# severity=None marks a "presence is GOOD" pattern (see missing_benchmarks)
# ---------------------------------------------------------------------------
SUBSTRATE_VULN_PATTERNS: dict[str, list[tuple[str, str, RiskLevel]]] = {
    "missing_weight": [
        (
            r"weight\s*=\s*Weight::zero\(\)",
            "Weight::zero() used — call has no declared cost, trivial DoS vector",
            RiskLevel.CRITICAL,
        ),
        (
            r"weight\s*=\s*0\b",
            "Hardcoded zero weight — call has no declared cost, trivial DoS vector",
            RiskLevel.CRITICAL,
        ),
    ],
    "unsafe_arithmetic": [
        (
            r"\bpanic!\s*\(",
            "Explicit panic!() — halts block execution and can brick the chain",
            RiskLevel.CRITICAL,
        ),
        (
            r"\.unwrap\s*\(\)",
            "unwrap() on Option/Result — panics on None/Err and halts block execution",
            RiskLevel.HIGH,
        ),
        (
            r"\.expect\s*\(",
            "expect() on Option/Result — panics on None/Err and halts block execution",
            RiskLevel.HIGH,
        ),
        (
            r"\bas\s+u(?:8|16|32|64|128|size)\b",
            "Unsafe numeric cast — may silently truncate; use checked/saturating conversion",
            RiskLevel.MEDIUM,
        ),
    ],
    "unsigned_transaction_abuse": [
        (
            r"\bValidateUnsigned\b",
            "Pallet implements ValidateUnsigned — verify replay protection and strict origin checks",
            RiskLevel.HIGH,
        ),
        (
            r"ensure_none\s*\(\s*origin\s*\)",
            "Unsigned extrinsic — ensure ValidateUnsigned provides strict rate-limiting and replay protection",
            RiskLevel.HIGH,
        ),
    ],
    "storage_without_deposit": [
        (
            r"StorageMap\s*<",
            "StorageMap detected — verify deposit enforcement to prevent unbounded state growth",
            RiskLevel.MEDIUM,
        ),
        (
            r"StorageDoubleMap\s*<",
            "StorageDoubleMap detected — verify deposit enforcement to prevent unbounded state growth",
            RiskLevel.MEDIUM,
        ),
        (
            r"StorageNMap\s*<",
            "StorageNMap detected — verify deposit enforcement to prevent unbounded state growth",
            RiskLevel.MEDIUM,
        ),
    ],
    "access_control": [
        (
            r"ensure_root\s*\(\s*origin\s*\)",
            "Root-only call — confirm this is intentional and sudo will be removed at mainnet",
            RiskLevel.LOW,
        ),
        (
            r"T\s*::\s*(?:ForceOrigin|AdminOrigin|GovernanceOrigin)\s*::\s*ensure_origin",
            "Custom governance origin — verify it is correctly configured in the runtime construct_runtime!",
            RiskLevel.LOW,
        ),
    ],
}

# Pattern whose *presence* signals safety (absence → vulnerability)
BENCHMARK_MARKER_RE = re.compile(
    r'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"runtime-benchmarks"\s*\)\s*\]',
    re.MULTILINE,
)


class SubstrateScanner:
    """Static vulnerability scanner for Substrate/FRAME pallet source code."""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compile_patterns() -> list[tuple[str, re.Pattern[str], str, RiskLevel]]:
        """Return a flat list of (vuln_type, compiled_re, description, severity)."""
        compiled = []
        for vuln_type, patterns in SUBSTRATE_VULN_PATTERNS.items():
            for pattern, description, severity in patterns:
                compiled.append(
                    (vuln_type, re.compile(pattern, re.MULTILINE), description, severity)
                )
        return compiled

    @staticmethod
    def _line_number(source: str, match_start: int) -> int:
        """Return 1-based line number for a character offset in source."""
        return source[:match_start].count("\n") + 1

    @staticmethod
    def _code_snippet(lines: list[str], line_number: int, context: int = 0) -> str:
        """Return the source line at *line_number* (1-based), stripped."""
        idx = line_number - 1
        start = max(0, idx - context)
        end = min(len(lines), idx + context + 1)
        return "\n".join(lines[start:end]).strip()

    @staticmethod
    def compute_risk_score(vulnerabilities: list[Vulnerability]) -> int:
        """Compute a 0–100 risk score from a list of vulnerabilities."""
        score = sum(SEVERITY_WEIGHTS.get(v.severity, 0) for v in vulnerabilities)
        return min(score, 100)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse_file(self, path: str) -> list[Vulnerability]:
        """Analyse a single Rust source file and return all findings.

        Args:
            path: Absolute or relative path to a ``.rs`` file.

        Returns:
            List of :class:`Vulnerability` instances (may be empty).
        """
        source = Path(path).read_text(encoding="utf-8", errors="replace")
        lines = source.splitlines()
        findings: list[Vulnerability] = []

        for vuln_type, pattern, description, severity in self._compile_patterns():
            for match in pattern.finditer(source):
                lineno = self._line_number(source, match.start())
                snippet = self._code_snippet(lines, lineno)
                findings.append(
                    Vulnerability(
                        type=vuln_type,
                        description=description,
                        severity=severity,
                        line_number=lineno,
                        code_snippet=snippet,
                    )
                )

        return findings

    def analyse_pallet(self, pallet_dir: str) -> PalletScanResult:
        """Analyse all Rust source files under *pallet_dir* as one pallet.

        Recursively scans every ``.rs`` file found under *pallet_dir*.
        Additionally checks for the presence of a ``runtime-benchmarks``
        feature gate; absence is recorded as a HIGH finding.

        Args:
            pallet_dir: Path to a directory containing Rust source files.

        Returns:
            :class:`PalletScanResult` with aggregated findings.
        """
        pallet_path = Path(pallet_dir)
        pallet_name = pallet_path.name

        rs_files = sorted(pallet_path.rglob("*.rs"))
        all_vulnerabilities: list[Vulnerability] = []
        has_benchmarks = False

        for rs_file in rs_files:
            all_vulnerabilities.extend(self.analyse_file(str(rs_file)))
            source = rs_file.read_text(encoding="utf-8", errors="replace")
            if BENCHMARK_MARKER_RE.search(source):
                has_benchmarks = True

        if not has_benchmarks:
            all_vulnerabilities.append(
                Vulnerability(
                    type="missing_benchmarks",
                    description=(
                        "No runtime-benchmarks feature gate found — pallet has no benchmarks; "
                        "weights may be inaccurate, enabling DoS via under-priced calls"
                    ),
                    severity=RiskLevel.HIGH,
                )
            )

        score = self.compute_risk_score(all_vulnerabilities)
        level = self._compute_risk_level(score)

        return PalletScanResult(
            pallet_name=pallet_name,
            pallet_path=str(pallet_path.resolve()),
            scan_timestamp=time.time(),
            vulnerabilities=all_vulnerabilities,
            risk_score=score,
            risk_level=level,
            files_scanned=len(rs_files),
            has_benchmarks=has_benchmarks,
        )

    def scan_chain(self, pallets_dir: str) -> ChainAuditReport:
        """Scan all pallets under *pallets_dir* and produce a chain-level report.

        A subdirectory is treated as a pallet if it contains a ``Cargo.toml``.

        Args:
            pallets_dir: Path to a directory whose subdirectories are pallets.

        Returns:
            :class:`ChainAuditReport` aggregating all pallet results.
        """
        root = Path(pallets_dir)
        pallet_dirs = sorted(
            d for d in root.iterdir() if d.is_dir() and (d / "Cargo.toml").exists()
        )

        pallet_results: list[PalletScanResult] = []
        for pallet_dir in pallet_dirs:
            pallet_results.append(self.analyse_pallet(str(pallet_dir)))

        total_vulns = sum(len(p.vulnerabilities) for p in pallet_results)
        critical_count = sum(
            1
            for p in pallet_results
            for v in p.vulnerabilities
            if v.severity == RiskLevel.CRITICAL
        )
        high_count = sum(
            1
            for p in pallet_results
            for v in p.vulnerabilities
            if v.severity == RiskLevel.HIGH
        )

        # Overall risk = worst single pallet risk level
        if any(p.risk_level == RiskLevel.CRITICAL for p in pallet_results):
            overall_risk = RiskLevel.CRITICAL
        elif any(p.risk_level == RiskLevel.HIGH for p in pallet_results):
            overall_risk = RiskLevel.HIGH
        elif any(p.risk_level == RiskLevel.MEDIUM for p in pallet_results):
            overall_risk = RiskLevel.MEDIUM
        else:
            overall_risk = RiskLevel.LOW

        return ChainAuditReport(
            pallets=pallet_results,
            total_vulnerabilities=total_vulns,
            critical_count=critical_count,
            high_count=high_count,
            overall_risk=overall_risk,
            scan_timestamp=time.time(),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_level(score: int) -> RiskLevel:
        if score >= 75:
            return RiskLevel.CRITICAL
        elif score >= 50:
            return RiskLevel.HIGH
        elif score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
