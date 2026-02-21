"""Tests for SubstrateScanner — Substrate/Rust pallet vulnerability scanner."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from shield_agent.models import (
    ChainAuditReport,
    PalletScanResult,
    RiskLevel,
    Vulnerability,
)
from shield_agent.substrate_scanner import (
    SEVERITY_WEIGHTS,
    SUBSTRATE_VULN_PATTERNS,
    SubstrateScanner,
)


# ---------------------------------------------------------------------------
# Rust source fixtures
# ---------------------------------------------------------------------------

CLEAN_RS = """
#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(T::WeightInfo::do_something())]
        pub fn do_something(origin: OriginFor<T>) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            Ok(())
        }
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking {
    use super::*;
    benchmarks! {
        do_something {}: _
    }
}
"""

PANIC_RS = """
pub fn dangerous(x: Option<u32>) -> u32 {
    panic!("something went wrong");
}
"""

UNWRAP_RS = """
pub fn get_value(map: &BTreeMap<u32, u32>, key: u32) -> u32 {
    *map.get(&key).unwrap()
}
"""

EXPECT_RS = """
pub fn decode(bytes: &[u8]) -> MyType {
    MyType::decode(&mut &bytes[..]).expect("decode failed")
}
"""

UNSAFE_CAST_RS = """
pub fn truncate(big: u128) -> u32 {
    big as u32
}
"""

ZERO_WEIGHT_RS = """
#[pallet::weight(weight = Weight::zero())]
pub fn free_call(origin: OriginFor<T>) -> DispatchResult {
    Ok(())
}
"""

ZERO_WEIGHT_INT_RS = """
#[pallet::weight(weight = 0)]
pub fn also_free(origin: OriginFor<T>) -> DispatchResult {
    Ok(())
}
"""

VALIDATE_UNSIGNED_RS = """
impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;
    fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
        Ok(ValidTransaction::default())
    }
}
"""

ENSURE_NONE_RS = """
pub fn submit_report(origin: OriginFor<T>, data: Vec<u8>) -> DispatchResult {
    ensure_none(origin)?;
    // process unsigned extrinsic
    Ok(())
}
"""

STORAGE_MAP_RS = """
#[pallet::storage]
pub type AgentIndex<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, AgentInfo<T>>;
"""

STORAGE_DOUBLE_MAP_RS = """
#[pallet::storage]
pub type Tasks<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat, T::AccountId,
    Blake2_128Concat, TaskId,
    TaskInfo<T>,
>;
"""

STORAGE_NMAP_RS = """
#[pallet::storage]
pub type Ratings<T: Config> = StorageNMap<_, (NMapKey<Blake2_128Concat, T::AccountId>,), u32>;
"""

ENSURE_ROOT_RS = """
pub fn set_param(origin: OriginFor<T>, value: u32) -> DispatchResult {
    ensure_root(origin)?;
    <Param<T>>::put(value);
    Ok(())
}
"""

CUSTOM_ORIGIN_RS = """
pub fn governance_action(origin: OriginFor<T>) -> DispatchResult {
    T::GovernanceOrigin::ensure_origin(origin)?;
    Ok(())
}
"""

NO_BENCHMARKS_RS = """
#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(T::WeightInfo::do_something())]
        pub fn do_something(origin: OriginFor<T>) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            Ok(())
        }
    }
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_rs(tmp_path: Path, filename: str, content: str) -> Path:
    """Write a .rs file to tmp_path and return its path."""
    p = tmp_path / filename
    p.write_text(content)
    return p


def _make_pallet_dir(tmp_path: Path, name: str, sources: dict[str, str], has_cargo: bool = True) -> Path:
    """Create a minimal pallet directory structure."""
    pallet_dir = tmp_path / name
    src_dir = pallet_dir / "src"
    src_dir.mkdir(parents=True)
    for fname, content in sources.items():
        (src_dir / fname).write_text(content)
    if has_cargo:
        (pallet_dir / "Cargo.toml").write_text(
            f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n'
        )
    return pallet_dir


# ---------------------------------------------------------------------------
# Unit tests: analyse_file
# ---------------------------------------------------------------------------


class TestAnalyseFileClean:
    def test_clean_source_no_findings(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", CLEAN_RS)
        scanner = SubstrateScanner()
        findings = scanner.analyse_file(str(f))
        # Clean source has benchmarks and no dangerous patterns;
        # only possible LOW access_control findings from ensure_signed — not matched.
        vuln_types = {v.type for v in findings}
        assert "unsafe_arithmetic" not in vuln_types
        assert "missing_weight" not in vuln_types
        assert "unsigned_transaction_abuse" not in vuln_types

    def test_returns_list(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", CLEAN_RS)
        result = SubstrateScanner().analyse_file(str(f))
        assert isinstance(result, list)


class TestAnalyseFilePanic:
    def test_detects_explicit_panic(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", PANIC_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        types = [v.type for v in findings]
        assert "unsafe_arithmetic" in types

    def test_panic_is_critical(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", PANIC_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        panics = [v for v in findings if "panic" in v.description.lower()]
        assert any(v.severity == RiskLevel.CRITICAL for v in panics)

    def test_panic_has_line_number(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", PANIC_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        for v in findings:
            assert v.line_number is not None and v.line_number > 0

    def test_panic_has_code_snippet(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", PANIC_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        for v in findings:
            assert v.code_snippet is not None and len(v.code_snippet) > 0


class TestAnalyseFileUnwrap:
    def test_detects_unwrap(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", UNWRAP_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "unsafe_arithmetic" for v in findings)

    def test_unwrap_is_high(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", UNWRAP_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        unwrap_findings = [v for v in findings if "unwrap" in v.description]
        assert any(v.severity == RiskLevel.HIGH for v in unwrap_findings)


class TestAnalyseFileExpect:
    def test_detects_expect(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", EXPECT_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "unsafe_arithmetic" for v in findings)

    def test_expect_is_high(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", EXPECT_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        expect_findings = [v for v in findings if "expect" in v.description]
        assert any(v.severity == RiskLevel.HIGH for v in expect_findings)


class TestAnalyseFileUnsafeCast:
    def test_detects_unsafe_cast(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", UNSAFE_CAST_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "unsafe_arithmetic" for v in findings)

    def test_unsafe_cast_is_medium(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", UNSAFE_CAST_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        cast_findings = [v for v in findings if "cast" in v.description]
        assert any(v.severity == RiskLevel.MEDIUM for v in cast_findings)


class TestAnalyseFileMissingWeight:
    def test_detects_weight_zero(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", ZERO_WEIGHT_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "missing_weight" for v in findings)

    def test_weight_zero_is_critical(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", ZERO_WEIGHT_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        wf = [v for v in findings if v.type == "missing_weight"]
        assert any(v.severity == RiskLevel.CRITICAL for v in wf)

    def test_detects_hardcoded_zero_weight(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", ZERO_WEIGHT_INT_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "missing_weight" for v in findings)


class TestAnalyseFileUnsignedTx:
    def test_detects_validate_unsigned(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", VALIDATE_UNSIGNED_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "unsigned_transaction_abuse" for v in findings)

    def test_validate_unsigned_is_high(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", VALIDATE_UNSIGNED_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        uf = [v for v in findings if v.type == "unsigned_transaction_abuse"]
        assert any(v.severity == RiskLevel.HIGH for v in uf)

    def test_detects_ensure_none(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", ENSURE_NONE_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "unsigned_transaction_abuse" for v in findings)


class TestAnalyseFileStorage:
    def test_detects_storage_map(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", STORAGE_MAP_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "storage_without_deposit" for v in findings)

    def test_storage_map_is_medium(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", STORAGE_MAP_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        sf = [v for v in findings if v.type == "storage_without_deposit"]
        assert any(v.severity == RiskLevel.MEDIUM for v in sf)

    def test_detects_storage_double_map(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", STORAGE_DOUBLE_MAP_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "storage_without_deposit" for v in findings)

    def test_detects_storage_nmap(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", STORAGE_NMAP_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "storage_without_deposit" for v in findings)


class TestAnalyseFileAccessControl:
    def test_detects_ensure_root(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", ENSURE_ROOT_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "access_control" for v in findings)

    def test_ensure_root_is_low(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", ENSURE_ROOT_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        rf = [v for v in findings if v.type == "access_control"]
        assert any(v.severity == RiskLevel.LOW for v in rf)

    def test_detects_custom_governance_origin(self, tmp_path):
        f = _write_rs(tmp_path, "lib.rs", CUSTOM_ORIGIN_RS)
        findings = SubstrateScanner().analyse_file(str(f))
        assert any(v.type == "access_control" for v in findings)


# ---------------------------------------------------------------------------
# Unit tests: compute_risk_score
# ---------------------------------------------------------------------------


class TestComputeRiskScore:
    def test_empty_returns_zero(self):
        assert SubstrateScanner.compute_risk_score([]) == 0

    def test_single_critical(self):
        v = Vulnerability(type="t", description="d", severity=RiskLevel.CRITICAL)
        assert SubstrateScanner.compute_risk_score([v]) == 50

    def test_single_high(self):
        v = Vulnerability(type="t", description="d", severity=RiskLevel.HIGH)
        assert SubstrateScanner.compute_risk_score([v]) == 30

    def test_single_medium(self):
        v = Vulnerability(type="t", description="d", severity=RiskLevel.MEDIUM)
        assert SubstrateScanner.compute_risk_score([v]) == 15

    def test_single_low(self):
        v = Vulnerability(type="t", description="d", severity=RiskLevel.LOW)
        assert SubstrateScanner.compute_risk_score([v]) == 5

    def test_capped_at_100(self):
        vulns = [Vulnerability(type="t", description="d", severity=RiskLevel.CRITICAL) for _ in range(5)]
        assert SubstrateScanner.compute_risk_score(vulns) == 100

    def test_mixed_severities(self):
        vulns = [
            Vulnerability(type="t", description="d", severity=RiskLevel.HIGH),
            Vulnerability(type="t", description="d", severity=RiskLevel.MEDIUM),
        ]
        assert SubstrateScanner.compute_risk_score(vulns) == 45

    def test_severity_weights_complete(self):
        for level in RiskLevel:
            assert level in SEVERITY_WEIGHTS


# ---------------------------------------------------------------------------
# Unit tests: analyse_pallet
# ---------------------------------------------------------------------------


class TestAnalysePallet:
    def test_returns_pallet_scan_result(self, tmp_path):
        pallet = _make_pallet_dir(tmp_path, "my-pallet", {"lib.rs": CLEAN_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert isinstance(result, PalletScanResult)

    def test_pallet_name_from_dir(self, tmp_path):
        pallet = _make_pallet_dir(tmp_path, "agent-did", {"lib.rs": CLEAN_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert result.pallet_name == "agent-did"

    def test_files_scanned_count(self, tmp_path):
        pallet = _make_pallet_dir(
            tmp_path, "pallet",
            {"lib.rs": CLEAN_RS, "tests.rs": "// tests", "benchmarking.rs": "// bench"}
        )
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert result.files_scanned == 3

    def test_has_benchmarks_true(self, tmp_path):
        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": CLEAN_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert result.has_benchmarks is True

    def test_has_benchmarks_false(self, tmp_path):
        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": NO_BENCHMARKS_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert result.has_benchmarks is False

    def test_missing_benchmarks_emits_high_finding(self, tmp_path):
        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": NO_BENCHMARKS_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        bench_findings = [v for v in result.vulnerabilities if v.type == "missing_benchmarks"]
        assert len(bench_findings) == 1
        assert bench_findings[0].severity == RiskLevel.HIGH

    def test_benchmarks_present_no_missing_finding(self, tmp_path):
        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": CLEAN_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        bench_findings = [v for v in result.vulnerabilities if v.type == "missing_benchmarks"]
        assert bench_findings == []

    def test_risk_score_computed(self, tmp_path):
        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": PANIC_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert result.risk_score > 0

    def test_risk_level_set(self, tmp_path):
        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": PANIC_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert result.risk_level in list(RiskLevel)

    def test_pallet_path_is_absolute(self, tmp_path):
        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": CLEAN_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert result.pallet_path.startswith("/")

    def test_scan_timestamp_is_recent(self, tmp_path):
        before = time.time()
        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": CLEAN_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert result.scan_timestamp >= before

    def test_multiple_files_aggregated(self, tmp_path):
        pallet = _make_pallet_dir(
            tmp_path, "pallet",
            {
                "lib.rs": CLEAN_RS,      # has benchmarks, no dangerous patterns
                "extra.rs": PANIC_RS,    # panic finding
            }
        )
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert any(v.type == "unsafe_arithmetic" for v in result.vulnerabilities)
        # Benchmarks found in lib.rs — no missing_benchmarks finding
        assert all(v.type != "missing_benchmarks" for v in result.vulnerabilities)


# ---------------------------------------------------------------------------
# Unit tests: scan_chain
# ---------------------------------------------------------------------------


class TestScanChain:
    def _setup_chain(self, tmp_path: Path) -> Path:
        """Create a minimal chain layout with two pallets."""
        pallets_dir = tmp_path / "pallets"
        pallets_dir.mkdir()
        _make_pallet_dir(pallets_dir, "pallet-clean", {"lib.rs": CLEAN_RS})
        _make_pallet_dir(pallets_dir, "pallet-dangerous", {"lib.rs": PANIC_RS})
        return pallets_dir

    def test_returns_chain_audit_report(self, tmp_path):
        pallets_dir = self._setup_chain(tmp_path)
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        assert isinstance(report, ChainAuditReport)

    def test_scans_all_pallets(self, tmp_path):
        pallets_dir = self._setup_chain(tmp_path)
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        assert len(report.pallets) == 2

    def test_chain_name_default(self, tmp_path):
        pallets_dir = self._setup_chain(tmp_path)
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        assert report.chain_name == "ClawChain"

    def test_total_vulnerabilities_summed(self, tmp_path):
        pallets_dir = self._setup_chain(tmp_path)
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        expected = sum(len(p.vulnerabilities) for p in report.pallets)
        assert report.total_vulnerabilities == expected

    def test_critical_count(self, tmp_path):
        pallets_dir = self._setup_chain(tmp_path)
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        expected = sum(
            1 for p in report.pallets
            for v in p.vulnerabilities
            if v.severity == RiskLevel.CRITICAL
        )
        assert report.critical_count == expected

    def test_high_count(self, tmp_path):
        pallets_dir = self._setup_chain(tmp_path)
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        expected = sum(
            1 for p in report.pallets
            for v in p.vulnerabilities
            if v.severity == RiskLevel.HIGH
        )
        assert report.high_count == expected

    def test_overall_risk_worst_pallet(self, tmp_path):
        pallets_dir = self._setup_chain(tmp_path)
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        worst = max((p.risk_level for p in report.pallets), key=lambda l: list(RiskLevel).index(l))
        assert report.overall_risk == worst

    def test_ignores_non_pallet_dirs(self, tmp_path):
        """Directories without Cargo.toml are skipped."""
        pallets_dir = tmp_path / "pallets"
        pallets_dir.mkdir()
        _make_pallet_dir(pallets_dir, "real-pallet", {"lib.rs": CLEAN_RS})
        # Non-pallet dir (no Cargo.toml)
        non_pallet = pallets_dir / "not-a-pallet"
        non_pallet.mkdir()
        (non_pallet / "lib.rs").write_text(PANIC_RS)
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        assert len(report.pallets) == 1
        assert report.pallets[0].pallet_name == "real-pallet"

    def test_empty_pallets_dir(self, tmp_path):
        pallets_dir = tmp_path / "pallets"
        pallets_dir.mkdir()
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        assert len(report.pallets) == 0
        assert report.total_vulnerabilities == 0
        assert report.overall_risk == RiskLevel.LOW

    def test_scan_timestamp_recent(self, tmp_path):
        before = time.time()
        pallets_dir = self._setup_chain(tmp_path)
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        assert report.scan_timestamp >= before


# ---------------------------------------------------------------------------
# Unit tests: PalletScanResult and ChainAuditReport dataclasses
# ---------------------------------------------------------------------------


class TestDataclasses:
    def test_pallet_scan_result_fields(self, tmp_path):
        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": CLEAN_RS})
        result = SubstrateScanner().analyse_pallet(str(pallet))
        assert hasattr(result, "pallet_name")
        assert hasattr(result, "pallet_path")
        assert hasattr(result, "scan_timestamp")
        assert hasattr(result, "vulnerabilities")
        assert hasattr(result, "risk_score")
        assert hasattr(result, "risk_level")
        assert hasattr(result, "files_scanned")
        assert hasattr(result, "has_benchmarks")

    def test_chain_audit_report_fields(self, tmp_path):
        pallets_dir = tmp_path / "pallets"
        pallets_dir.mkdir()
        report = SubstrateScanner().scan_chain(str(pallets_dir))
        assert hasattr(report, "pallets")
        assert hasattr(report, "total_vulnerabilities")
        assert hasattr(report, "critical_count")
        assert hasattr(report, "high_count")
        assert hasattr(report, "overall_risk")
        assert hasattr(report, "scan_timestamp")
        assert hasattr(report, "chain_name")


# ---------------------------------------------------------------------------
# Unit tests: SUBSTRATE_VULN_PATTERNS completeness
# ---------------------------------------------------------------------------


class TestPatternCompleteness:
    def test_expected_categories_present(self):
        expected = {
            "missing_weight",
            "unsafe_arithmetic",
            "unsigned_transaction_abuse",
            "storage_without_deposit",
            "access_control",
        }
        assert expected.issubset(set(SUBSTRATE_VULN_PATTERNS.keys()))

    def test_all_patterns_have_three_elements(self):
        for category, patterns in SUBSTRATE_VULN_PATTERNS.items():
            for entry in patterns:
                assert len(entry) == 3, f"{category}: entry should have (pattern, desc, severity)"

    def test_all_severities_are_risk_level(self):
        for category, patterns in SUBSTRATE_VULN_PATTERNS.items():
            for _, _, severity in patterns:
                assert isinstance(severity, RiskLevel)


# ---------------------------------------------------------------------------
# Integration: CLI scan-pallet and audit-chain
# ---------------------------------------------------------------------------


class TestCLIScanPallet:
    def test_scan_pallet_clean(self, tmp_path):
        from click.testing import CliRunner
        from shield_agent.cli import main

        pallet = _make_pallet_dir(tmp_path, "clean-pallet", {"lib.rs": CLEAN_RS})
        runner = CliRunner()
        result = runner.invoke(main, ["scan-pallet", str(pallet)])
        assert result.exit_code == 0
        assert "clean-pallet" in result.output

    def test_scan_pallet_json_output(self, tmp_path):
        from click.testing import CliRunner
        from shield_agent.cli import main

        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": PANIC_RS})
        runner = CliRunner()
        result = runner.invoke(main, ["scan-pallet", str(pallet), "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "pallet_name" in data
        assert "vulnerabilities" in data
        assert data["risk_score"] > 0

    def test_scan_pallet_with_attest(self, tmp_path):
        from click.testing import CliRunner
        from unittest.mock import patch, MagicMock
        from shield_agent.cli import main
        from shield_agent.attestation import AttestationResult

        pallet = _make_pallet_dir(tmp_path, "pallet", {"lib.rs": CLEAN_RS})
        mock_att = AttestationResult(success=True, tx_hash="0xabc123", block_number=None, error=None)
        runner = CliRunner()
        with patch("shield_agent.attestation.attest_scan", return_value=mock_att):
            result = runner.invoke(main, ["scan-pallet", str(pallet), "--attest"])
        assert result.exit_code == 0


class TestCLIAuditChain:
    def test_audit_chain_clean_exit_zero(self, tmp_path):
        from click.testing import CliRunner
        from shield_agent.cli import main

        pallets_dir = tmp_path / "pallets"
        pallets_dir.mkdir()
        # Only LOW/MEDIUM findings — no CRITICAL/HIGH → exit 0
        _make_pallet_dir(pallets_dir, "pallet-a", {"lib.rs": STORAGE_MAP_RS + "\n" + CLEAN_RS})
        runner = CliRunner()
        result = runner.invoke(main, ["audit-chain", str(pallets_dir)])
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_audit_chain_critical_exit_one(self, tmp_path):
        from click.testing import CliRunner
        from shield_agent.cli import main

        pallets_dir = tmp_path / "pallets"
        pallets_dir.mkdir()
        _make_pallet_dir(pallets_dir, "pallet-bad", {"lib.rs": PANIC_RS})
        runner = CliRunner()
        result = runner.invoke(main, ["audit-chain", str(pallets_dir)])
        assert result.exit_code == 1
        assert "FAIL" in result.output

    def test_audit_chain_json_output(self, tmp_path):
        from click.testing import CliRunner
        from shield_agent.cli import main

        pallets_dir = tmp_path / "pallets"
        pallets_dir.mkdir()
        _make_pallet_dir(pallets_dir, "pallet-a", {"lib.rs": CLEAN_RS})
        runner = CliRunner()
        result = runner.invoke(main, ["audit-chain", str(pallets_dir), "--output", "json"])
        data = json.loads(result.output)
        assert "pallets" in data
        assert "critical_count" in data
        assert "overall_risk" in data

    def test_audit_chain_json_exit_one_on_critical(self, tmp_path):
        from click.testing import CliRunner
        from shield_agent.cli import main

        pallets_dir = tmp_path / "pallets"
        pallets_dir.mkdir()
        _make_pallet_dir(pallets_dir, "bad", {"lib.rs": PANIC_RS})
        runner = CliRunner()
        result = runner.invoke(main, ["audit-chain", str(pallets_dir), "--output", "json"])
        assert result.exit_code == 1
