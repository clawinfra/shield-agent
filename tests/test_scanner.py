"""Tests for ShieldAgent scanner."""

import time
from unittest.mock import patch, MagicMock

import pytest

from shield_agent.models import RiskLevel, ScanResult, Vulnerability
from shield_agent.scanner import ContractScanner


class TestScanResultStructure:
    """Test that ScanResult has all required fields."""

    def test_scan_result_structure(self):
        result = ScanResult(
            contract_address="0xDEAD",
            contract_name="TestContract",
            scan_timestamp=time.time(),
            vulnerabilities=[],
            risk_score=0,
            risk_level=RiskLevel.LOW,
            source_available=True,
        )
        assert result.contract_address == "0xDEAD"
        assert result.contract_name == "TestContract"
        assert isinstance(result.scan_timestamp, float)
        assert result.vulnerabilities == []
        assert result.risk_score == 0
        assert result.risk_level == RiskLevel.LOW
        assert result.source_available is True


class TestRiskScoring:
    """Test risk score computation."""

    def test_empty_vulns_score_zero(self):
        scanner = ContractScanner()
        assert scanner.compute_risk_score([]) == 0

    def test_risk_scoring(self):
        scanner = ContractScanner()
        vulns = [
            Vulnerability(type="reentrancy", description="test", severity=RiskLevel.CRITICAL),
            Vulnerability(type="access_control", description="test", severity=RiskLevel.HIGH),
        ]
        score = scanner.compute_risk_score(vulns)
        # CRITICAL=50 + HIGH=30 = 80
        assert score == 80

    def test_risk_level_boundaries(self):
        assert ScanResult.compute_risk_level(0) == RiskLevel.LOW
        assert ScanResult.compute_risk_level(24) == RiskLevel.LOW
        assert ScanResult.compute_risk_level(25) == RiskLevel.MEDIUM
        assert ScanResult.compute_risk_level(49) == RiskLevel.MEDIUM
        assert ScanResult.compute_risk_level(50) == RiskLevel.HIGH
        assert ScanResult.compute_risk_level(74) == RiskLevel.HIGH
        assert ScanResult.compute_risk_level(75) == RiskLevel.CRITICAL
        assert ScanResult.compute_risk_level(100) == RiskLevel.CRITICAL

    def test_score_capped_at_100(self):
        scanner = ContractScanner()
        vulns = [
            Vulnerability(type="a", description="x", severity=RiskLevel.CRITICAL),
            Vulnerability(type="b", description="x", severity=RiskLevel.CRITICAL),
            Vulnerability(type="c", description="x", severity=RiskLevel.CRITICAL),
        ]
        score = scanner.compute_risk_score(vulns)
        assert score == 100  # 50*3 = 150, capped to 100


class TestKnownVulnDetection:
    """Test that known vulnerability patterns are detected."""

    REENTRANCY_SOURCE = """
    pragma solidity ^0.8.0;
    contract Vulnerable {
        mapping(address => uint) public balances;
        function withdraw() public {
            uint bal = balances[msg.sender];
            (bool sent, ) = msg.sender.call{value: bal}("");
            require(sent, "Failed");
            balances[msg.sender] = 0;  // state change AFTER external call!
        }
    }
    """

    TX_ORIGIN_SOURCE = """
    pragma solidity ^0.8.0;
    contract Phishable {
        address public owner;
        function transferOwnership(address _new) public {
            require(tx.origin == owner);
            owner = _new;
        }
    }
    """

    def test_detects_reentrancy_pattern(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.REENTRANCY_SOURCE)
        types = [v.type for v in vulns]
        assert "reentrancy" in types

    def test_detects_tx_origin(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.TX_ORIGIN_SOURCE)
        types = [v.type for v in vulns]
        assert "access_control" in types
        # Should be CRITICAL severity
        tx_origin_vulns = [v for v in vulns if "tx.origin" in v.description]
        assert any(v.severity == RiskLevel.CRITICAL for v in tx_origin_vulns)


class TestFetchSourceHandlesErrors:
    """Test that fetch_source gracefully handles errors."""

    def test_fetch_source_handles_network_error(self):
        scanner = ContractScanner()
        with patch("shield_agent.scanner.requests.get", side_effect=Exception("Network error")):
            result = scanner.fetch_source("0xDEAD")
        assert result["source"] == ""
        assert result["name"] == ""

    def test_fetch_source_handles_bad_json(self):
        scanner = ContractScanner()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "0", "result": "Error"}
        mock_resp.raise_for_status = MagicMock()
        with patch("shield_agent.scanner.requests.get", return_value=mock_resp):
            result = scanner.fetch_source("0xDEAD")
        assert result["source"] == ""


class TestPocAddressList:
    """Ensure the PoC address list is complete."""

    def test_poc_addresses_list_complete(self):
        from shield_agent.poc_scan import TOP_DEFI_CONTRACTS

        assert len(TOP_DEFI_CONTRACTS) == 10
        for contract in TOP_DEFI_CONTRACTS:
            assert "name" in contract
            assert "address" in contract
            assert contract["address"].startswith("0x")
            assert len(contract["address"]) == 42
