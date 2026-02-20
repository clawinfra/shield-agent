"""Tests for ShieldAgent CLI."""

from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from shield_agent.cli import main, _risk_colour
from shield_agent.models import RiskLevel, ScanResult, Vulnerability


@pytest.fixture
def runner():
    return CliRunner()


class TestRiskColour:
    """Test _risk_colour helper."""

    def test_low(self):
        assert _risk_colour(RiskLevel.LOW) == "green"

    def test_medium(self):
        assert _risk_colour(RiskLevel.MEDIUM) == "yellow"

    def test_high(self):
        assert _risk_colour(RiskLevel.HIGH) == "red"

    def test_critical(self):
        assert _risk_colour(RiskLevel.CRITICAL) == "bold red"


class TestScanCommand:
    """Test the 'scan' CLI command."""

    def test_scan_dry_run(self, runner):
        result = runner.invoke(main, ["scan", "0xDEADBEEF", "--dry-run"])
        assert result.exit_code == 0
        assert "Source code not available" in result.output

    def test_scan_with_source(self, runner):
        scan_result = ScanResult(
            contract_address="0xDEAD",
            contract_name="TestToken",
            source_available=True,
            vulnerabilities=[
                Vulnerability(
                    type="reentrancy",
                    description="Reentrancy detected",
                    severity=RiskLevel.CRITICAL,
                    line_number=42,
                ),
            ],
            risk_score=50,
            risk_level=RiskLevel.HIGH,
        )
        with patch(
            "shield_agent.cli.ContractScanner"
        ) as MockScanner:
            MockScanner.return_value.scan.return_value = scan_result
            result = runner.invoke(main, ["scan", "0xDEAD"])
        assert result.exit_code == 0
        assert "TestToken" in result.output
        assert "reentrancy" in result.output

    def test_scan_no_vulns(self, runner):
        scan_result = ScanResult(
            contract_address="0xDEAD",
            contract_name="Clean",
            source_available=True,
            vulnerabilities=[],
            risk_score=0,
            risk_level=RiskLevel.LOW,
        )
        with patch(
            "shield_agent.cli.ContractScanner"
        ) as MockScanner:
            MockScanner.return_value.scan.return_value = scan_result
            result = runner.invoke(main, ["scan", "0xDEAD"])
        assert result.exit_code == 0
        assert "0/100" in result.output


class TestMonitorCommand:
    """Test the 'monitor' CLI command."""

    def test_monitor_keyboard_interrupt(self, runner):
        scan_result = ScanResult(
            contract_address="0xDEAD",
            contract_name="Token",
            source_available=True,
            vulnerabilities=[],
            risk_score=0,
            risk_level=RiskLevel.LOW,
        )
        with patch(
            "shield_agent.cli.ContractScanner"
        ) as MockScanner, patch("shield_agent.cli.time") as mock_time:
            MockScanner.return_value.scan.return_value = scan_result
            mock_time.strftime.return_value = "12:00:00"
            mock_time.sleep.side_effect = KeyboardInterrupt()
            result = runner.invoke(main, ["monitor", "0xDEAD", "--dry-run"])
        assert "Monitoring stopped" in result.output

    def test_monitor_dry_run(self, runner):
        scan_result = ScanResult(
            contract_address="0xDEAD",
            contract_name="(dry-run)",
            source_available=False,
            risk_score=0,
            risk_level=RiskLevel.LOW,
        )
        with patch(
            "shield_agent.cli.ContractScanner"
        ) as MockScanner, patch("shield_agent.cli.time") as mock_time:
            MockScanner.return_value.scan.return_value = scan_result
            mock_time.strftime.return_value = "12:00:00"
            mock_time.sleep.side_effect = KeyboardInterrupt()
            result = runner.invoke(main, ["monitor", "0xDEAD", "--dry-run"])
        assert result.exit_code == 0


class TestReportCommand:
    """Test the 'report' CLI command."""

    def test_report_placeholder(self, runner):
        result = runner.invoke(main, ["report", "scan-123"])
        assert result.exit_code == 0
        assert "v0.3" in result.output


class TestVersionFlag:
    """Test --version flag."""

    def test_version(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
