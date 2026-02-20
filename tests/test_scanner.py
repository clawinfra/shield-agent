"""Tests for ShieldAgent scanner."""

import time
from unittest.mock import patch, MagicMock

import pytest

from shield_agent.models import RiskLevel, ScanResult, Vulnerability
from shield_agent.scanner import ContractScanner, VULN_PATTERNS, SEVERITY_WEIGHTS


# ------------------------------------------------------------------ #
# ScanResult structure
# ------------------------------------------------------------------ #


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

    def test_scan_result_defaults(self):
        result = ScanResult(contract_address="0x1", contract_name="X")
        assert result.risk_score == 0
        assert result.risk_level == RiskLevel.LOW
        assert result.source_available is False
        assert result.vulnerabilities == []


# ------------------------------------------------------------------ #
# Risk scoring
# ------------------------------------------------------------------ #


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

    def test_severity_weights_complete(self):
        """Every RiskLevel has a weight."""
        for level in RiskLevel:
            assert level in SEVERITY_WEIGHTS

    def test_single_low_vuln(self):
        scanner = ContractScanner()
        vulns = [Vulnerability(type="x", description="x", severity=RiskLevel.LOW)]
        assert scanner.compute_risk_score(vulns) == 5

    def test_single_medium_vuln(self):
        scanner = ContractScanner()
        vulns = [Vulnerability(type="x", description="x", severity=RiskLevel.MEDIUM)]
        assert scanner.compute_risk_score(vulns) == 15


# ------------------------------------------------------------------ #
# Vulnerability pattern detection
# ------------------------------------------------------------------ #


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

    SELFDESTRUCT_SOURCE = """
    pragma solidity ^0.8.0;
    contract Destructible {
        address payable owner;
        function kill() public {
            selfdestruct(owner);
        }
    }
    """

    DELEGATECALL_SOURCE = """
    pragma solidity ^0.8.0;
    contract Proxy {
        address impl;
        fallback() external payable {
            (bool ok, ) = impl.delegatecall(msg.data);
            require(ok);
        }
    }
    """

    UNCHECKED_MATH_SOURCE = """
    pragma solidity ^0.8.0;
    contract UncheckedMath {
        function unsafeAdd(uint a, uint b) public pure returns (uint) {
            unchecked {
                return a + b;
            }
        }
    }
    """

    OLD_SOLIDITY_SOURCE = """
    pragma solidity ^0.6.0;
    contract Old {
        uint public x;
        function add(uint a) public {
            x += a;
        }
    }
    """

    SEND_SOURCE = """
    pragma solidity ^0.8.0;
    contract PayMe {
        function pay(address payable to) public {
            to.send(1 ether);
        }
    }
    """

    FLASH_LOAN_SOURCE = """
    pragma solidity ^0.8.0;
    contract FL {
        function flashLoan(uint amount) external {}
    }
    """

    ORACLE_SOURCE = """
    pragma solidity ^0.8.0;
    interface IUniswap {
        function getReserves() external view returns (uint, uint, uint);
    }
    contract OracleUser {
        function price(address pair) external view returns (uint) {
            (uint r0, uint r1,) = IUniswap(pair).getReserves();
            return r0 * 1e18 / r1;
        }
    }
    """

    OLD_CALL_VALUE_SOURCE = """
    pragma solidity ^0.6.0;
    contract OldStyle {
        function send(address payable to) public {
            to.call.value(1 ether)("");
        }
    }
    """

    SUICIDE_SOURCE = """
    pragma solidity ^0.4.0;
    contract Legacy {
        function kill() public {
            suicide(msg.sender);
        }
    }
    """

    CHAINLINK_SOURCE = """
    pragma solidity ^0.8.0;
    interface AggregatorV3 {
        function latestRoundData() external view returns (uint80, int256, uint, uint, uint80);
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
        tx_origin_vulns = [v for v in vulns if "tx.origin" in v.description]
        assert any(v.severity == RiskLevel.CRITICAL for v in tx_origin_vulns)

    def test_detects_selfdestruct(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.SELFDESTRUCT_SOURCE)
        types = [v.type for v in vulns]
        assert "access_control" in types
        sd_vulns = [v for v in vulns if "selfdestruct" in v.description.lower()]
        assert len(sd_vulns) >= 1

    def test_detects_delegatecall(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.DELEGATECALL_SOURCE)
        types = [v.type for v in vulns]
        assert "access_control" in types

    def test_detects_unchecked_math(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.UNCHECKED_MATH_SOURCE)
        types = [v.type for v in vulns]
        assert "integer_overflow" in types

    def test_detects_old_solidity_version(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.OLD_SOLIDITY_SOURCE)
        types = [v.type for v in vulns]
        assert "integer_overflow" in types

    def test_detects_send(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.SEND_SOURCE)
        types = [v.type for v in vulns]
        assert "unchecked_return" in types

    def test_detects_flash_loan(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.FLASH_LOAN_SOURCE)
        types = [v.type for v in vulns]
        assert "flash_loan" in types

    def test_detects_oracle_manipulation(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.ORACLE_SOURCE)
        types = [v.type for v in vulns]
        assert "price_oracle_manipulation" in types

    def test_detects_old_call_value(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.OLD_CALL_VALUE_SOURCE)
        types = [v.type for v in vulns]
        assert "reentrancy" in types

    def test_detects_suicide(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.SUICIDE_SOURCE)
        types = [v.type for v in vulns]
        assert "access_control" in types

    def test_detects_chainlink_oracle(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.CHAINLINK_SOURCE)
        types = [v.type for v in vulns]
        assert "price_oracle_manipulation" in types

    def test_no_vulns_in_clean_source(self):
        clean = """
        pragma solidity ^0.8.0;
        contract Clean {
            uint public x;
            function set(uint _x) public { x = _x; }
        }
        """
        scanner = ContractScanner()
        vulns = scanner.analyse_source(clean)
        assert vulns == []

    def test_vuln_has_line_number(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.TX_ORIGIN_SOURCE)
        for v in vulns:
            assert v.line_number is not None
            assert v.line_number > 0

    def test_vuln_has_code_snippet(self):
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.TX_ORIGIN_SOURCE)
        for v in vulns:
            assert v.code_snippet is not None
            assert len(v.code_snippet) > 0

    def test_multiple_vulns_in_same_source(self):
        """Source with both reentrancy and tx.origin should flag both."""
        combined = """
        pragma solidity ^0.8.0;
        contract Multi {
            mapping(address => uint) public balances;
            function withdraw() public {
                require(tx.origin == msg.sender);
                (bool ok, ) = msg.sender.call{value: balances[msg.sender]}("");
                require(ok);
                balances[msg.sender] = 0;
            }
        }
        """
        scanner = ContractScanner()
        vulns = scanner.analyse_source(combined)
        types = set(v.type for v in vulns)
        assert "reentrancy" in types
        assert "access_control" in types

    def test_occurrence_count_in_description(self):
        """Description should include occurrence count."""
        scanner = ContractScanner()
        vulns = scanner.analyse_source(self.TX_ORIGIN_SOURCE)
        tx_vulns = [v for v in vulns if "tx.origin" in v.description]
        assert any("1 occurrence" in v.description for v in tx_vulns)


# ------------------------------------------------------------------ #
# Source fetching — Etherscan
# ------------------------------------------------------------------ #


class TestFetchSourceEtherscan:
    """Test Etherscan source fetching."""

    def test_fetch_etherscan_success(self):
        scanner = ContractScanner(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "status": "1",
            "result": [
                {
                    "ContractName": "TestToken",
                    "SourceCode": "pragma solidity ^0.8.0; contract T {}",
                    "CompilerVersion": "v0.8.20",
                    "ABI": "[{}]",
                }
            ],
        }
        with patch("shield_agent.scanner.requests.get", return_value=mock_resp):
            result = scanner._fetch_etherscan("0xDEAD")
        assert result is not None
        assert result["name"] == "TestToken"
        assert "pragma" in result["source"]
        assert result["compiler"] == "v0.8.20"

    def test_fetch_etherscan_empty_source(self):
        scanner = ContractScanner()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "status": "1",
            "result": [{"ContractName": "", "SourceCode": "", "CompilerVersion": "", "ABI": ""}],
        }
        with patch("shield_agent.scanner.requests.get", return_value=mock_resp):
            result = scanner._fetch_etherscan("0xDEAD")
        assert result is None

    def test_fetch_etherscan_bad_status(self):
        scanner = ContractScanner()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"status": "0", "result": "Error"}
        with patch("shield_agent.scanner.requests.get", return_value=mock_resp):
            result = scanner._fetch_etherscan("0xDEAD")
        assert result is None

    def test_fetch_etherscan_network_error(self):
        scanner = ContractScanner()
        with patch("shield_agent.scanner.requests.get", side_effect=Exception("Timeout")):
            result = scanner._fetch_etherscan("0xDEAD")
        assert result is None

    def test_fetch_etherscan_sends_api_key(self):
        scanner = ContractScanner(api_key="MY_KEY")
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"status": "0", "result": "Error"}
        with patch("shield_agent.scanner.requests.get", return_value=mock_resp) as mock_get:
            scanner._fetch_etherscan("0xDEAD")
        call_kwargs = mock_get.call_args
        assert "MY_KEY" in str(call_kwargs)


# ------------------------------------------------------------------ #
# Source fetching — Sourcify
# ------------------------------------------------------------------ #


class TestFetchSourceSourcify:
    """Test Sourcify source fetching."""

    def test_fetch_sourcify_perfect_match(self):
        scanner = ContractScanner()
        addr = "0xDEADBEEF"

        check_resp = MagicMock()
        check_resp.raise_for_status = MagicMock()
        check_resp.json.return_value = [
            {"address": addr, "status": "perfect", "chainIds": ["1"]}
        ]

        meta_resp = MagicMock()
        meta_resp.raise_for_status = MagicMock()
        meta_resp.json.return_value = {
            "sources": {
                "Contract.sol": {"content": "pragma solidity ^0.8.0; contract X {}"}
            },
            "compiler": {"version": "0.8.20"},
            "output": {"devdoc": {"title": "My Contract"}},
        }

        with patch("shield_agent.scanner.requests.get") as mock_get:
            mock_get.side_effect = [check_resp, meta_resp]
            result = scanner._fetch_sourcify(addr)

        assert result is not None
        assert "pragma" in result["source"]
        assert result["compiler"] == "0.8.20"

    def test_fetch_sourcify_partial_match(self):
        scanner = ContractScanner()
        addr = "0xDEADBEEF"

        check_resp = MagicMock()
        check_resp.raise_for_status = MagicMock()
        check_resp.json.return_value = [
            {"address": addr, "status": "partial", "chainIds": ["1"]}
        ]

        meta_resp = MagicMock()
        meta_resp.raise_for_status = MagicMock()
        meta_resp.json.return_value = {
            "sources": {
                "Contract.sol": {"content": "pragma solidity ^0.8.0; contract X {}"}
            },
            "compiler": {"version": "0.8.19"},
            "output": {},
        }

        with patch("shield_agent.scanner.requests.get") as mock_get:
            mock_get.side_effect = [check_resp, meta_resp]
            result = scanner._fetch_sourcify(addr)

        assert result is not None
        assert "pragma" in result["source"]

    def test_fetch_sourcify_no_match(self):
        scanner = ContractScanner()
        check_resp = MagicMock()
        check_resp.raise_for_status = MagicMock()
        check_resp.json.return_value = []

        with patch("shield_agent.scanner.requests.get", return_value=check_resp):
            result = scanner._fetch_sourcify("0xDEAD")
        assert result is None

    def test_fetch_sourcify_empty_sources(self):
        scanner = ContractScanner()
        addr = "0xDEADBEEF"

        check_resp = MagicMock()
        check_resp.raise_for_status = MagicMock()
        check_resp.json.return_value = [
            {"address": addr, "status": "perfect", "chainIds": ["1"]}
        ]

        meta_resp = MagicMock()
        meta_resp.raise_for_status = MagicMock()
        meta_resp.json.return_value = {"sources": {}, "compiler": {}, "output": {}}

        with patch("shield_agent.scanner.requests.get") as mock_get:
            mock_get.side_effect = [check_resp, meta_resp]
            result = scanner._fetch_sourcify(addr)
        assert result is None

    def test_fetch_sourcify_network_error(self):
        scanner = ContractScanner()
        with patch("shield_agent.scanner.requests.get", side_effect=Exception("Net")):
            result = scanner._fetch_sourcify("0xDEAD")
        assert result is None

    def test_fetch_sourcify_address_case_insensitive(self):
        """Sourcify address matching should be case-insensitive."""
        scanner = ContractScanner()
        addr_upper = "0xDEADBEEF"

        check_resp = MagicMock()
        check_resp.raise_for_status = MagicMock()
        check_resp.json.return_value = [
            {"address": "0xdeadbeef", "status": "perfect", "chainIds": ["1"]}
        ]

        meta_resp = MagicMock()
        meta_resp.raise_for_status = MagicMock()
        meta_resp.json.return_value = {
            "sources": {"C.sol": {"content": "contract X {}"}},
            "compiler": {"version": "0.8.0"},
            "output": {},
        }

        with patch("shield_agent.scanner.requests.get") as mock_get:
            mock_get.side_effect = [check_resp, meta_resp]
            result = scanner._fetch_sourcify(addr_upper)
        assert result is not None


# ------------------------------------------------------------------ #
# Unified fetch_source fallback
# ------------------------------------------------------------------ #


class TestFetchSourceFallback:
    """Test multi-provider fallback in fetch_source."""

    def test_etherscan_success_skips_sourcify(self):
        scanner = ContractScanner()
        with patch.object(
            scanner, "_fetch_etherscan", return_value={"name": "E", "source": "code", "compiler": "", "abi": ""}
        ) as eth, patch.object(scanner, "_fetch_sourcify") as src:
            result = scanner.fetch_source("0x1")
        assert result["source"] == "code"
        eth.assert_called_once()
        src.assert_not_called()

    def test_etherscan_fail_falls_to_sourcify(self):
        scanner = ContractScanner()
        with patch.object(scanner, "_fetch_etherscan", return_value=None), patch.object(
            scanner,
            "_fetch_sourcify",
            return_value={"name": "S", "source": "src", "compiler": "", "abi": ""},
        ) as src:
            result = scanner.fetch_source("0x1")
        assert result["source"] == "src"
        src.assert_called_once()

    def test_both_fail_returns_empty(self):
        scanner = ContractScanner()
        with patch.object(scanner, "_fetch_etherscan", return_value=None), patch.object(
            scanner, "_fetch_sourcify", return_value=None
        ):
            result = scanner.fetch_source("0x1")
        assert result["source"] == ""
        assert result["name"] == ""

    def test_etherscan_empty_source_falls_to_sourcify(self):
        """Etherscan returning empty string source triggers Sourcify."""
        scanner = ContractScanner()
        with patch.object(
            scanner, "_fetch_etherscan", return_value={"name": "", "source": "", "compiler": "", "abi": ""}
        ), patch.object(
            scanner,
            "_fetch_sourcify",
            return_value={"name": "S", "source": "fallback", "compiler": "", "abi": ""},
        ):
            result = scanner.fetch_source("0x1")
        assert result["source"] == "fallback"

    def test_fetch_source_handles_network_error(self):
        """Legacy test: network error results in empty."""
        scanner = ContractScanner()
        with patch("shield_agent.scanner.requests.get", side_effect=Exception("Network error")):
            result = scanner.fetch_source("0xDEAD")
        assert result["source"] == ""
        assert result["name"] == ""


# ------------------------------------------------------------------ #
# Full scan pipeline
# ------------------------------------------------------------------ #


class TestScanPipeline:
    """Test the full scan() method."""

    def test_dry_run_returns_empty(self):
        scanner = ContractScanner()
        result = scanner.scan("0xDEAD", dry_run=True)
        assert result.contract_name == "(dry-run)"
        assert result.source_available is False

    def test_scan_with_source(self):
        scanner = ContractScanner()
        source_data = {
            "name": "TestToken",
            "source": "pragma solidity ^0.8.0; contract T { function f() public { } }",
            "compiler": "",
            "abi": "",
        }
        with patch.object(scanner, "fetch_source", return_value=source_data):
            result = scanner.scan("0xDEAD")
        assert result.source_available is True
        assert result.contract_name == "TestToken"

    def test_scan_no_source(self):
        scanner = ContractScanner()
        with patch.object(
            scanner, "fetch_source", return_value={"name": "", "source": "", "compiler": "", "abi": ""}
        ):
            result = scanner.scan("0xDEAD")
        assert result.source_available is False


# ------------------------------------------------------------------ #
# PoC address list
# ------------------------------------------------------------------ #


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
