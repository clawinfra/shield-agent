"""Tests for PoC scan module — demo mode, CLI args, and attestation wiring."""

from unittest.mock import patch, MagicMock

import pytest

from shield_agent.models import RiskLevel
from shield_agent.poc_scan import (
    DEMO_VULNERABLE_CONTRACTS,
    TOP_DEFI_CONTRACTS,
    main,
    run_demo_scan,
    run_poc_scan,
)


class TestDemoContracts:
    """Test the demo vulnerable contracts dictionary."""

    def test_demo_contracts_not_empty(self):
        assert len(DEMO_VULNERABLE_CONTRACTS) >= 2

    def test_demo_contracts_have_required_keys(self):
        for name, info in DEMO_VULNERABLE_CONTRACTS.items():
            assert "source" in info, f"{name} missing 'source'"
            assert "address" in info, f"{name} missing 'address'"
            assert "expected_vuln" in info, f"{name} missing 'expected_vuln'"
            assert len(info["source"].strip()) > 0, f"{name} has empty source"

    def test_reentrancy_demo_present(self):
        assert "ReentrancyDemo" in DEMO_VULNERABLE_CONTRACTS

    def test_tx_origin_demo_present(self):
        assert "TxOriginDemo" in DEMO_VULNERABLE_CONTRACTS


class TestRunDemoScan:
    """Test run_demo_scan produces real vulnerability results."""

    def test_demo_scan_returns_results(self):
        results = run_demo_scan(attest=False)
        assert len(results) == len(DEMO_VULNERABLE_CONTRACTS)

    def test_demo_scan_finds_vulnerabilities(self):
        results = run_demo_scan(attest=False)
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        assert total_vulns > 0, "Demo scan should find at least some vulnerabilities"

    def test_demo_scan_reentrancy_detected(self):
        results = run_demo_scan(attest=False)
        reentrancy_result = [r for r in results if "Reentrancy" in r.contract_name]
        assert len(reentrancy_result) == 1
        types = [v.type for v in reentrancy_result[0].vulnerabilities]
        assert "reentrancy" in types

    def test_demo_scan_tx_origin_detected(self):
        results = run_demo_scan(attest=False)
        tx_result = [r for r in results if "TxOrigin" in r.contract_name]
        assert len(tx_result) == 1
        types = [v.type for v in tx_result[0].vulnerabilities]
        assert "access_control" in types

    def test_demo_scan_all_have_source(self):
        results = run_demo_scan(attest=False)
        for r in results:
            assert r.source_available is True

    def test_demo_scan_with_attest(self):
        """Demo scan with --attest calls attest_scan for each result."""
        with patch("shield_agent.poc_scan.attest_scan") as mock_attest:
            results = run_demo_scan(attest=True)
        assert mock_attest.call_count == len(DEMO_VULNERABLE_CONTRACTS)


class TestRunPocScan:
    """Test run_poc_scan with mocked network."""

    def test_poc_scan_dry_run(self):
        results = run_poc_scan(attest=False, dry_run=True)
        assert len(results) == len(TOP_DEFI_CONTRACTS)
        for r in results:
            assert r.source_available is False

    def test_poc_scan_with_attest_dry_run(self):
        with patch("shield_agent.poc_scan.attest_scan") as mock_attest:
            run_poc_scan(attest=True, dry_run=True)
        assert mock_attest.call_count == len(TOP_DEFI_CONTRACTS)


class TestMainEntryPoint:
    """Test the CLI argument parser."""

    def test_main_demo_flag(self):
        with patch("shield_agent.poc_scan.run_demo_scan") as mock:
            main(["--demo"])
        mock.assert_called_once_with(attest=False)

    def test_main_demo_with_attest(self):
        with patch("shield_agent.poc_scan.run_demo_scan") as mock:
            main(["--demo", "--attest"])
        mock.assert_called_once_with(attest=True)

    def test_main_dry_run(self):
        with patch("shield_agent.poc_scan.run_poc_scan") as mock:
            main(["--dry-run"])
        mock.assert_called_once_with(attest=False, dry_run=True)

    def test_main_default_runs_poc(self):
        with patch("shield_agent.poc_scan.run_poc_scan") as mock:
            main([])
        mock.assert_called_once_with(attest=False, dry_run=False)
